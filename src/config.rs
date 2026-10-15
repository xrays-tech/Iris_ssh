//! Configuration: TOML parsing + validation into a trusted runtime config.
//!
//! The config file is an untrusted input, so it is first deserialized into
//! `Raw*` structs whose human-facing fields (sizes, durations, socket addrs)
//! are still plain strings, then validated field-by-field into [`GatewayConfig`]
//! whose fields are already typed (`u32` bytes, [`Duration`], [`HostKeyPolicy`]).
//! Validation is a set of small pure functions so each rule is unit-testable and
//! reports the offending field name (fail fast, fail loud).

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
    /// External control plane. `None` only when the gateway runs in OpenStack
    /// pure mode (`routing = "openstack_only"`), where no control plane exists
    /// (plan-openstack §0-7 / §3.6).
    pub control_plane: Option<ControlPlaneConfig>,
    /// OpenStack instance-UUID routing (plan-openstack §3.6). `None` when the
    /// section is absent or `enabled = false` — the default, which leaves the
    /// gateway byte-for-byte unchanged.
    pub openstack: Option<OpenStackConfig>,
    pub limits: LimitsConfig,
    /// Certificate authority (B1: host/user CA).
    pub ca: CaConfig,
    /// SFTP command-level interception (B3).
    pub intercept: InterceptConfig,
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

/// Backend-leg settings.
///
/// There is no credential here any more: the gateway authenticates to the
/// backend with the end user's forwarded ssh-agent and holds no key material of
/// its own (plan-agent-only). `private_key`, `credential_map`, `backend_auth`
/// and `allow_agent_backend_auth` were removed with it; a config file that
/// still sets them is simply ignored (the config parser is permissive).
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub host_key_policy: HostKeyPolicy,
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

// --------------------------------------------------------------------------
// OpenStack instance-UUID routing (plan-openstack §3.5 / §3.6).
//
// `routing` (which resolver answers) and `authorization` (who decides) are
// deliberately two separate knobs — see plan-openstack §3.5. Only two of the
// four combinations are legal; the other two are rejected at validation time
// so a gateway can never silently authorize OpenStack grants outside the
// control plane.
// --------------------------------------------------------------------------

/// Which resolver serves a principal (plan-openstack §3.1 / F2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpenStackRouting {
    /// UUID-shaped principals resolve through OpenStack, everything else through
    /// the control plane. Requires `authorization = "openstack_only"`, which in
    /// turn requires the danger flag — so `hybrid` cannot be enabled until the
    /// control-plane authorization variant (scheme A) exists.
    #[default]
    Hybrid,
    /// Only UUID-shaped principals are accepted; there is no control-plane
    /// fallback for anything else, and `[control_plane]` may be omitted.
    OpenStackOnly,
}

/// Who authorizes a principal (plan-openstack §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpenStackAuthorization {
    /// The control plane remains the sole authorization authority (red line 1).
    #[default]
    ControlPlane,
    /// **Lab mode**: any key that passes front-leg signature verification may
    /// reach any UUID it can name. Requires `allow_any_authenticated_key`.
    OpenStackOnly,
}

/// Which shapes of principal the OpenStack route will accept
/// (plan-openstack appendix A.1).
///
/// Configured as `[openstack] route_by = [...]`; the default is `["uuid"]`,
/// which is byte-for-byte the behaviour that existed before name routing
/// landed. UUID-shaped principals always take the UUID route when it is
/// enabled — a name is never consulted for them, so "an instance whose name
/// happens to look like a UUID" cannot create ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// Canonical instance UUID, resolved by `GET /servers/{id}`.
    Uuid,
    /// Instance name, resolved by `GET /servers?name=` with a local
    /// exact-match filter (Nova's filter is a substring/RE search).
    Name,
}

impl RouteKind {
    /// The stable token used in `[openstack] route_by` and in log fields.
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::Uuid => "uuid",
            RouteKind::Name => "name",
        }
    }
}

impl std::fmt::Display for RouteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Keystone v3 authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpenStackAuthMethod {
    #[default]
    ApplicationCredential,
    /// Escape hatch for tests / short-lived tooling: a pre-issued `X-Auth-Token`.
    Token,
}

/// Which endpoint interface to pick from the service catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EndpointInterface {
    #[default]
    Public,
    Internal,
    Admin,
}

/// IP version filter for the selected instance address (plan-openstack §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressFamily {
    #[default]
    IPv4,
    IPv6,
    /// Keep both families; ordering still applies.
    Any,
}

/// Whether floating or fixed addresses win when both exist (plan-openstack §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpPrefer {
    #[default]
    Floating,
    Fixed,
    /// Prefer floating (best cross-network reachability) but never fail on
    /// ties between types.
    Any,
}

/// What to do when more than one address survives filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnAmbiguous {
    /// Fail loud (default): a wrong guess could cross a network security zone.
    #[default]
    Reject,
    /// Take the first address in stable (network, addr) order and warn.
    First,
}

/// One `[[openstack.backend_user_map]]` rule (plan-openstack §3.4).
///
/// All present conditions are AND-ed; a rule with no condition at all is
/// rejected at validation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendUserRule {
    /// Instance-name matcher. Empty = "no name condition"; a leading `^`
    /// selects *prefix* matching, otherwise the match is exact.
    pub match_name: String,
    /// Metadata entries that must all be present with equal values.
    pub match_metadata: std::collections::BTreeMap<String, String>,
    /// Backend login user to use when this rule matches.
    pub user: String,
}

/// Validated `[openstack]` section.
///
/// `Debug` is hand-written so the application-credential secret and the static
/// token are never rendered into logs, `{:?}` diagnostics or test failures.
#[derive(Clone)]
pub struct OpenStackConfig {
    pub routing: OpenStackRouting,
    pub authorization: OpenStackAuthorization,
    pub allow_any_authenticated_key: bool,
    /// Which principal shapes this route accepts. Default `["uuid"]`; adding
    /// `"name"` opts in to instance-name routing (plan-openstack appendix A.1).
    pub route_by: Vec<RouteKind>,

    // --- Keystone v3 -----------------------------------------------------
    pub auth_url: String,
    pub auth_method: OpenStackAuthMethod,
    pub application_credential_id: String,
    /// Resolved from `application_credential_secret_file` → literal value →
    /// `$SSHGW_OPENSTACK_APPLICATION_CREDENTIAL_SECRET` (first non-empty wins).
    pub application_credential_secret: String,
    /// Resolved the same way from `token_file` → `token` →
    /// `$SSHGW_OPENSTACK_TOKEN`; only used with `auth_method = "token"`.
    pub token: String,
    /// Token scope. Strongly recommended: it is the blast-radius gate on which
    /// instances this gateway can see at all (plan-openstack §3.2 / R5).
    pub project_id: String,
    pub region: String,
    pub interface: EndpointInterface,
    /// Explicit Nova base URL; skips catalog lookup (tests / internal clouds).
    pub nova_endpoint: String,
    pub microversion: String,

    // --- transport / caching ---------------------------------------------
    pub timeout: Duration,
    /// TTL of the instance-IP cache, independent of `control_plane.cache_ttl`.
    pub cache_ttl: Duration,
    /// Serve a stale IP when Nova is unreachable. Requires
    /// `[backend] host_key_policy = "pinned"` (plan-openstack red line 5).
    pub fail_open: bool,
    pub verify_tls: bool,
    /// Custom CA bundle; empty means the system roots.
    pub ca_bundle: PathBuf,

    // --- address selection (plan-openstack §3.3) ---------------------------
    /// Network name filter; empty accepts any network.
    pub network: String,
    pub address_family: AddressFamily,
    pub prefer: IpPrefer,
    pub on_ambiguous: OnAmbiguous,

    // --- backend login user (plan-openstack §3.4) --------------------------
    pub default_backend_user: String,
    pub backend_user_metadata_key: String,
    pub backend_user_map: Vec<BackendUserRule>,

    pub ssh_port: u16,
    pub recording: bool,
}

impl std::fmt::Debug for OpenStackConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenStackConfig")
            .field("routing", &self.routing)
            .field("authorization", &self.authorization)
            .field(
                "allow_any_authenticated_key",
                &self.allow_any_authenticated_key,
            )
            .field("route_by", &self.route_by)
            .field("auth_url", &self.auth_url)
            .field("auth_method", &self.auth_method)
            .field("application_credential_id", &self.application_credential_id)
            .field("application_credential_secret", &"<redacted>")
            .field("token", &"<redacted>")
            .field("project_id", &self.project_id)
            .field("region", &self.region)
            .field("interface", &self.interface)
            .field("nova_endpoint", &self.nova_endpoint)
            .field("microversion", &self.microversion)
            .field("timeout", &self.timeout)
            .field("cache_ttl", &self.cache_ttl)
            .field("fail_open", &self.fail_open)
            .field("verify_tls", &self.verify_tls)
            .field("ca_bundle", &self.ca_bundle)
            .field("network", &self.network)
            .field("address_family", &self.address_family)
            .field("prefer", &self.prefer)
            .field("on_ambiguous", &self.on_ambiguous)
            .field("default_backend_user", &self.default_backend_user)
            .field("backend_user_metadata_key", &self.backend_user_metadata_key)
            .field("backend_user_map", &self.backend_user_map)
            .field("ssh_port", &self.ssh_port)
            .field("recording", &self.recording)
            .finish()
    }
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
    ///
    /// Verify-only: `signing_key` / `cert_lifetime` are gone with the key/cert
    /// backend credential (plan-agent-only D3).
    pub trusted_ca_keys: Vec<std::path::PathBuf>,
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
    control_plane: Option<RawControlPlane>,
    #[serde(default)]
    openstack: Option<RawOpenStack>,
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
    recording: RawRecording,
}

#[derive(Debug, Deserialize, Default)]
struct RawCa {
    #[serde(default)]
    trusted_ca_keys: Vec<String>,
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
    host_key_policy: String,
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

// --- [openstack] raw shape (plan-openstack §3.6) ---------------------------

#[derive(Debug, Deserialize)]
struct RawOpenStack {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_routing")]
    routing: String,
    #[serde(default = "default_authorization")]
    authorization: String,
    #[serde(default)]
    allow_any_authenticated_key: bool,
    #[serde(default = "default_route_by")]
    route_by: Vec<String>,

    // Keystone
    #[serde(default)]
    auth_url: String,
    #[serde(default = "default_auth_method")]
    auth_method: String,
    #[serde(default)]
    application_credential_id: String,
    #[serde(default)]
    application_credential_secret: String,
    #[serde(default)]
    application_credential_secret_file: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    token_file: String,
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    region: String,
    #[serde(default = "default_interface")]
    interface: String,
    #[serde(default)]
    nova_endpoint: String,
    #[serde(default = "default_microversion")]
    microversion: String,

    // transport / caching
    #[serde(default = "default_openstack_timeout")]
    timeout: String,
    #[serde(default = "default_openstack_cache_ttl")]
    cache_ttl: String,
    #[serde(default)]
    fail_open: bool,
    #[serde(default = "default_verify_tls")]
    verify_tls: bool,
    #[serde(default)]
    ca_bundle: String,

    // address selection
    #[serde(default)]
    network: String,
    #[serde(default = "default_address_family")]
    address_family: String,
    #[serde(default = "default_prefer")]
    prefer: String,
    #[serde(default = "default_on_ambiguous")]
    on_ambiguous: String,

    // backend login user
    #[serde(default)]
    default_backend_user: String,
    #[serde(default)]
    backend_user_metadata_key: String,
    #[serde(default)]
    backend_user_map: Vec<RawBackendUserRule>,

    #[serde(default = "default_ssh_port")]
    ssh_port: u16,
    #[serde(default)]
    recording: bool,
}

#[derive(Debug, Deserialize)]
struct RawBackendUserRule {
    #[serde(default)]
    match_name: String,
    #[serde(default)]
    match_metadata: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    user: String,
}

fn default_routing() -> String {
    "hybrid".to_owned()
}
fn default_authorization() -> String {
    "control_plane".to_owned()
}
fn default_route_by() -> Vec<String> {
    // Conservative: only the UUID route exists unless an operator names the
    // name route explicitly (plan-openstack appendix A.1).
    vec!["uuid".to_owned()]
}
fn default_auth_method() -> String {
    "application_credential".to_owned()
}
fn default_interface() -> String {
    "public".to_owned()
}
fn default_address_family() -> String {
    "ipv4".to_owned()
}
fn default_prefer() -> String {
    "floating".to_owned()
}
fn default_on_ambiguous() -> String {
    "reject".to_owned()
}

fn default_microversion() -> String {
    "2.1".to_owned()
}
fn default_openstack_timeout() -> String {
    "3s".to_owned()
}
fn default_openstack_cache_ttl() -> String {
    "30s".to_owned()
}
fn default_verify_tls() -> bool {
    true
}
fn default_ssh_port() -> u16 {
    22
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
        let backend = BackendConfig { host_key_policy };

        // The gateway never shares a backend connection across sessions: its
        // identity is per-session (the end user's own forwarded agent), so a
        // pooled connection cannot carry "which user does the next channel
        // belong to" (propose §3.8). Now that agent auth is the *only* backend
        // auth, this fires unconditionally — `[pool] enabled = true` is simply
        // a configuration error, surfaced at boot rather than mid-session.
        if raw.pool.enabled {
            return Err(ConfigError::Invalid {
                field: "pool.enabled".into(),
                reason: "must be false: backend authentication is agent-forwarding based \
                         and needs a per-session connection (propose §3.8)"
                    .into(),
            });
        }
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

        // --- [openstack]: instance-UUID routing (plan-openstack §3.6) ------
        // Enum spellings are checked even when the section is disabled (a typo
        // should fail at boot, not silently disable the feature); `enabled =
        // false` then turns the whole section off, so no other combination rule
        // can keep an operator from switching it back off.
        let openstack = validate_openstack(raw.openstack, host_key_policy)?;

        // `[control_plane]` is required in every routing mode except the
        // OpenStack pure mode, where the gateway talks to no control plane at
        // all (plan-openstack §0-7).
        let control_plane_required =
            !matches!(&openstack, Some(os) if os.routing == OpenStackRouting::OpenStackOnly);
        let control_plane = match raw.control_plane {
            None if control_plane_required => {
                return Err(ConfigError::Invalid {
                    field: "control_plane".into(),
                    reason: "section is required unless [openstack] is enabled with \
                             routing = \"openstack_only\""
                        .into(),
                });
            }
            None => None,
            Some(cp) => {
                if cp.url.trim().is_empty() {
                    return Err(ConfigError::Invalid {
                        field: "control_plane.url".into(),
                        reason: "must not be empty".into(),
                    });
                }
                Some(ControlPlaneConfig {
                    url: cp.url.trim().to_owned(),
                    cache_ttl: parse_duration("control_plane.cache_ttl", &cp.cache_ttl)?,
                    timeout: parse_duration("control_plane.timeout", &cp.timeout)?,
                    fail_open: cp.fail_open,
                    cache_ttl_jitter: parse_duration(
                        "control_plane.cache_ttl_jitter",
                        &cp.cache_ttl_jitter,
                    )?,
                })
            }
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
        // An absent `[ca]` section is a valid, fully-opt-in "CA disabled"
        // configuration: nothing must require it. The CA is verify-only — it
        // gates front-leg user certificates and backend host certificates, and
        // no longer issues anything (plan-agent-only D3).
        let ca = CaConfig {
            trusted_ca_keys: raw
                .ca
                .trusted_ca_keys
                .iter()
                .map(|p| PathBuf::from(p.trim()))
                .collect(),
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
            openstack,
            limits,
            ca,
            intercept,
            recording,
            shutdown,
            metrics: MetricsConfig { addr: metrics_addr },
        })
    }
}

// --------------------------------------------------------------------------
// [openstack] validation (plan-openstack §3.6).
//
// Everything here is pure apart from reading a secret file; every rule reports
// the offending `openstack.*` field so an operator can fix the file without a
// debugger. Combination rules run *before* the `enabled` early-return because
// a disabled section with a contradictory pair is still a landmine left for
// whoever flips `enabled = true`.
// --------------------------------------------------------------------------

/// Validate the whole `[openstack]` section.
///
/// Returns `Ok(None)` when the section is absent or disabled: no OpenStack
/// resolver exists, and (red line 8) nothing about existing behaviour changes.
fn validate_openstack(
    raw: Option<RawOpenStack>,
    host_key_policy: HostKeyPolicy,
) -> std::result::Result<Option<OpenStackConfig>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };

    // --- enums (always) ---------------------------------------------------
    let routing = parse_routing(&raw.routing)?;
    let authorization = parse_authorization(&raw.authorization)?;
    let auth_method = parse_auth_method(&raw.auth_method)?;
    let interface = parse_interface(&raw.interface)?;
    let address_family = parse_address_family(&raw.address_family)?;
    let prefer = parse_prefer(&raw.prefer)?;
    let on_ambiguous = parse_on_ambiguous(&raw.on_ambiguous)?;
    // Parsed before the `enabled = false` short-circuit, exactly like the
    // enums above: a typo in a line the operator did write must fail the boot
    // rather than lie in wait until the feature is switched on.
    let route_by = parse_route_by(&raw.route_by)?;

    // `enabled = false` short-circuits everything below: the section is then
    // inert, so a leftover `routing`/`authorization` line can never stand in
    // the way of turning the feature back off (an operator must not have to
    // remember a second field to disable a resolver).
    if !raw.enabled {
        return Ok(None);
    }

    // --- combination rules (all of them only while the feature is on) -----
    // 1. routing = openstack_only ⇒ authorization = openstack_only.
    //    A "control_plane" authority with no control plane configured would
    //    advertise an authorization source that is never consulted.
    if routing == OpenStackRouting::OpenStackOnly
        && authorization != OpenStackAuthorization::OpenStackOnly
    {
        return Err(ConfigError::Invalid {
            field: "openstack.authorization".into(),
            reason: "routing = \"openstack_only\" requires authorization = \"openstack_only\": \
                     with no control plane left in the path, \"control_plane\" would name an \
                     authority that is never consulted"
                .into(),
        });
    }
    // 2. authorization = openstack_only ⇒ routing = openstack_only.
    //    Hybrid + openstack_only authorization would give one gateway two
    //    authorization semantics (plan-openstack §3.5 refuses to offer it),
    //    and hybrid + control_plane authorization would require the
    //    control-plane-authorization scheme (A), which is not implemented.
    if authorization == OpenStackAuthorization::OpenStackOnly
        && routing != OpenStackRouting::OpenStackOnly
    {
        return Err(ConfigError::Invalid {
            field: "openstack.routing".into(),
            reason: "authorization = \"openstack_only\" requires routing = \"openstack_only\": \
                     the hybrid authorization variant (control plane authorizes, OpenStack only \
                     resolves an address) is not implemented, so a hybrid route would authorize \
                     outside the control plane (plan-openstack §3.5)"
                .into(),
        });
    }
    // 3. authorization = openstack_only ⇒ explicit danger flag.
    if authorization == OpenStackAuthorization::OpenStackOnly && !raw.allow_any_authenticated_key {
        return Err(ConfigError::Invalid {
            field: "openstack.allow_any_authenticated_key".into(),
            reason: "must be set to true explicitly: openstack_only authorization means any \
                     key that passes front-leg signature verification can reach any instance \
                     UUID it knows (plan-openstack §3.5 R1)"
                .into(),
        });
    }
    // --- enabled: only the pure mode exists until scheme A lands -----------
    if routing != OpenStackRouting::OpenStackOnly {
        return Err(ConfigError::Invalid {
            field: "openstack.routing".into(),
            reason: "hybrid cannot be enabled while authorization = \"control_plane\": the \
                     control-plane authorization variant (plan-openstack §3.5 scheme A) is not \
                     implemented, so a hybrid route would resolve UUIDs through OpenStack \
                     without the control plane ever authorizing them. Set \
                     routing = \"openstack_only\" (plus authorization and \
                     allow_any_authenticated_key), or disable [openstack]"
                .into(),
        });
    }

    // --- Keystone ----------------------------------------------------------
    let auth_url = raw.auth_url.trim().to_owned();
    if auth_url.is_empty() {
        return Err(ConfigError::Invalid {
            field: "openstack.auth_url".into(),
            reason: "must not be empty when [openstack] is enabled".into(),
        });
    }
    if !auth_url.starts_with("https://") && !auth_url.starts_with("http://") {
        return Err(ConfigError::Invalid {
            field: "openstack.auth_url".into(),
            reason: format!(
                "not an absolute http(s) URL: {auth_url:?} (expected e.g. \
                 \"https://keystone.example:5000/v3\")"
            ),
        });
    }

    let nova_endpoint = raw.nova_endpoint.trim().to_owned();
    if !nova_endpoint.is_empty()
        && !nova_endpoint.starts_with("https://")
        && !nova_endpoint.starts_with("http://")
    {
        return Err(ConfigError::Invalid {
            field: "openstack.nova_endpoint".into(),
            reason: format!("not an absolute http(s) URL: {nova_endpoint:?}"),
        });
    }

    let application_credential_id = raw.application_credential_id.trim().to_owned();
    let application_credential_secret = resolve_secret(
        "openstack.application_credential_secret_file",
        &raw.application_credential_secret_file,
        &raw.application_credential_secret,
        std::env::var("SSHGW_OPENSTACK_APPLICATION_CREDENTIAL_SECRET")
            .ok()
            .as_deref(),
    )?;
    let token = resolve_secret(
        "openstack.token_file",
        &raw.token_file,
        &raw.token,
        std::env::var("SSHGW_OPENSTACK_TOKEN").ok().as_deref(),
    )?;
    match auth_method {
        OpenStackAuthMethod::ApplicationCredential => {
            if application_credential_id.is_empty() {
                return Err(ConfigError::Invalid {
                    field: "openstack.application_credential_id".into(),
                    reason: "must not be empty when auth_method = \"application_credential\""
                        .into(),
                });
            }
            if application_credential_secret.is_empty() {
                return Err(ConfigError::Invalid {
                    field: "openstack.application_credential_secret".into(),
                    reason: "required: set the literal value, \
                             openstack.application_credential_secret_file, or the \
                             SSHGW_OPENSTACK_APPLICATION_CREDENTIAL_SECRET environment variable"
                        .into(),
                });
            }
        }
        OpenStackAuthMethod::Token => {
            // A static token carries no service catalog, so there is nothing to
            // discover Nova from: the endpoint has to be stated.
            if raw.nova_endpoint.trim().is_empty() {
                return Err(ConfigError::Invalid {
                    field: "openstack.nova_endpoint".into(),
                    reason: "required when auth_method = \"token\": a static token has no \
                             service catalog, so there is nothing to discover Nova from"
                        .into(),
                });
            }
            if token.is_empty() {
                return Err(ConfigError::Invalid {
                    field: "openstack.token".into(),
                    reason: "required when auth_method = \"token\": set the literal value, \
                             openstack.token_file, or the SSHGW_OPENSTACK_TOKEN environment \
                             variable"
                        .into(),
                });
            }
        }
    }

    // --- transport / caching ----------------------------------------------
    let timeout = parse_duration("openstack.timeout", &raw.timeout)?;
    if timeout.is_zero() {
        return Err(ConfigError::Invalid {
            field: "openstack.timeout".into(),
            reason: "must be > 0".into(),
        });
    }
    let cache_ttl = parse_duration("openstack.cache_ttl", &raw.cache_ttl)?;
    if cache_ttl.is_zero() {
        return Err(ConfigError::Invalid {
            field: "openstack.cache_ttl".into(),
            reason: "must be > 0".into(),
        });
    }
    // Red line 5: a stale instance IP is only safe to dial if the backend host
    // key pins the *right* instance, otherwise a recycled address turns
    // fail-open into a man-in-the-middle on ourselves.
    if raw.fail_open && host_key_policy != HostKeyPolicy::Pinned {
        return Err(ConfigError::Invalid {
            field: "openstack.fail_open".into(),
            reason: "requires [backend] host_key_policy = \"pinned\": serving a stale instance \
                     address is only safe if host-key verification rejects the wrong instance \
                     (plan-openstack §5.2 red line 5)"
                .into(),
        });
    }
    let microversion = raw.microversion.trim().to_owned();
    if microversion.is_empty() {
        return Err(ConfigError::Invalid {
            field: "openstack.microversion".into(),
            reason: "must not be empty".into(),
        });
    }

    // --- backend login user (plan-openstack §3.4) --------------------------
    let default_backend_user = raw.default_backend_user.trim().to_owned();
    if default_backend_user.is_empty() {
        return Err(ConfigError::Invalid {
            field: "openstack.default_backend_user".into(),
            reason: "required when [openstack] is enabled: there is no universal default login \
                     name across cloud images, so the fallback must be stated"
                .into(),
        });
    }
    validate_backend_user(&default_backend_user, "openstack.default_backend_user")?;

    let backend_user_metadata_key = raw.backend_user_metadata_key.trim().to_owned();
    if backend_user_metadata_key.chars().any(char::is_control) {
        return Err(ConfigError::Invalid {
            field: "openstack.backend_user_metadata_key".into(),
            reason: "must not contain control characters".into(),
        });
    }

    let mut backend_user_map = Vec::with_capacity(raw.backend_user_map.len());
    for (idx, rule) in raw.backend_user_map.into_iter().enumerate() {
        let field = format!("openstack.backend_user_map[{idx}]");
        if rule.match_name.is_empty() && rule.match_metadata.is_empty() {
            return Err(ConfigError::Invalid {
                field: field.clone(),
                reason: "rule has no condition: give it match_name and/or match_metadata \
                         (an unconditional rule would override default_backend_user for \
                         every instance)"
                    .into(),
            });
        }
        if !rule.match_name.is_empty() {
            validate_name_pattern(&rule.match_name, &format!("{field}.match_name"))?;
        }
        for key in rule.match_metadata.keys() {
            if key.is_empty() {
                return Err(ConfigError::Invalid {
                    field: format!("{field}.match_metadata"),
                    reason: "metadata key must not be empty".into(),
                });
            }
        }
        validate_backend_user(&rule.user, &format!("{field}.user"))?;
        backend_user_map.push(BackendUserRule {
            match_name: rule.match_name,
            match_metadata: rule.match_metadata,
            user: rule.user,
        });
    }

    let ssh_port = raw.ssh_port;
    if ssh_port == 0 {
        return Err(ConfigError::Invalid {
            field: "openstack.ssh_port".into(),
            reason: "must be within [1, 65535]".into(),
        });
    }

    Ok(Some(OpenStackConfig {
        routing,
        authorization,
        allow_any_authenticated_key: raw.allow_any_authenticated_key,
        route_by,
        auth_url,
        auth_method,
        application_credential_id,
        application_credential_secret,
        token,
        project_id: raw.project_id.trim().to_owned(),
        region: raw.region.trim().to_owned(),
        interface,
        nova_endpoint,
        microversion,
        timeout,
        cache_ttl,
        fail_open: raw.fail_open,
        verify_tls: raw.verify_tls,
        ca_bundle: PathBuf::from(raw.ca_bundle.trim()),
        network: raw.network.trim().to_owned(),
        address_family,
        prefer,
        on_ambiguous,
        default_backend_user,
        backend_user_metadata_key,
        backend_user_map,
        ssh_port,
        recording: raw.recording,
    }))
}

/// Resolve a secret from file → literal → environment value, first non-empty
/// wins. Reading the file at load time means a bad path fails the boot, not the
/// first login attempt.
///
/// The environment value is passed in rather than read here so the precedence
/// rules are testable without mutating process-global state (which would race
/// with the other config tests running in parallel).
fn resolve_secret(
    file_field: &str,
    file: &str,
    literal: &str,
    env_value: Option<&str>,
) -> std::result::Result<String, ConfigError> {
    if !file.trim().is_empty() {
        let path = PathBuf::from(file.trim());
        let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::ReadFile {
            path: path.clone(),
            source,
        })?;
        // Strip the trailing newline editors insist on adding; keep the rest.
        let text = text.trim_end_matches(['\n', '\r']);
        if text.is_empty() {
            return Err(ConfigError::Invalid {
                field: file_field.to_owned(),
                reason: format!("secret file {path:?} is empty"),
            });
        }
        return Ok(text.to_owned());
    }
    if !literal.is_empty() {
        return Ok(literal.to_owned());
    }
    if let Some(value) = env_value {
        if !value.is_empty() {
            return Ok(value.to_owned());
        }
    }
    // Left empty on purpose: the caller reports which field is missing.
    Ok(String::new())
}

/// Backend login user: non-empty, no whitespace, no control characters. It is
/// handed verbatim to the backend's `service username` request, so anything
/// that could smuggle protocol structure is rejected here (fail loud at boot,
/// plan-openstack §3.4).
fn validate_backend_user(value: &str, field: &str) -> std::result::Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::Invalid {
            field: field.to_owned(),
            reason: "must not be empty".into(),
        });
    }
    if let Some(bad) = value.chars().find(|c| c.is_whitespace() || c.is_control()) {
        return Err(ConfigError::Invalid {
            field: field.to_owned(),
            reason: format!("must not contain whitespace or control characters (found {bad:?})"),
        });
    }
    Ok(())
}

/// `match_name` supports exact match, or prefix match when it starts with `^`.
/// Regex quantifiers/grouping are *not* supported (plan-openstack §3.4: v1 is
/// exact/prefix only), and a pattern that looks like regex is rejected rather
/// than silently matched literally — a too-narrow rule fails every login.
fn validate_name_pattern(value: &str, field: &str) -> std::result::Result<(), ConfigError> {
    const REGEX_ONLY: &[char] = &['*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '\\', '$'];
    let body = value.strip_prefix('^').unwrap_or(value);
    if body.is_empty() {
        return Err(ConfigError::Invalid {
            field: field.to_owned(),
            reason: "prefix pattern after '^' must not be empty".into(),
        });
    }
    if let Some(c) = body.chars().find(|c| REGEX_ONLY.contains(c)) {
        return Err(ConfigError::Invalid {
            field: field.to_owned(),
            reason: format!(
                "unsupported regular-expression metacharacter {c:?}: only exact match, or \
                 prefix match when the pattern starts with '^' (plan-openstack §3.4)"
            ),
        });
    }
    if body.contains('^') {
        return Err(ConfigError::Invalid {
            field: field.to_owned(),
            reason: "'^' is only allowed once, at the very start".into(),
        });
    }
    Ok(())
}

fn enum_error(field: &str, value: &str, expected: &str) -> ConfigError {
    ConfigError::Invalid {
        field: field.to_owned(),
        reason: format!("unknown value {value:?} (expected {expected})"),
    }
}

fn parse_routing(value: &str) -> std::result::Result<OpenStackRouting, ConfigError> {
    match value.trim() {
        "hybrid" => Ok(OpenStackRouting::Hybrid),
        "openstack_only" => Ok(OpenStackRouting::OpenStackOnly),
        other => Err(enum_error(
            "openstack.routing",
            other,
            "\"hybrid\" or \"openstack_only\"",
        )),
    }
}

fn parse_authorization(value: &str) -> std::result::Result<OpenStackAuthorization, ConfigError> {
    match value.trim() {
        "control_plane" => Ok(OpenStackAuthorization::ControlPlane),
        "openstack_only" => Ok(OpenStackAuthorization::OpenStackOnly),
        other => Err(enum_error(
            "openstack.authorization",
            other,
            "\"control_plane\" or \"openstack_only\"",
        )),
    }
}

fn parse_auth_method(value: &str) -> std::result::Result<OpenStackAuthMethod, ConfigError> {
    match value.trim() {
        "application_credential" => Ok(OpenStackAuthMethod::ApplicationCredential),
        "token" => Ok(OpenStackAuthMethod::Token),
        other => Err(enum_error(
            "openstack.auth_method",
            other,
            "\"application_credential\" or \"token\"",
        )),
    }
}

fn parse_interface(value: &str) -> std::result::Result<EndpointInterface, ConfigError> {
    match value.trim() {
        "public" => Ok(EndpointInterface::Public),
        "internal" => Ok(EndpointInterface::Internal),
        "admin" => Ok(EndpointInterface::Admin),
        other => Err(enum_error(
            "openstack.interface",
            other,
            "\"public\", \"internal\" or \"admin\"",
        )),
    }
}

fn parse_address_family(value: &str) -> std::result::Result<AddressFamily, ConfigError> {
    match value.trim() {
        "ipv4" => Ok(AddressFamily::IPv4),
        "ipv6" => Ok(AddressFamily::IPv6),
        "any" => Ok(AddressFamily::Any),
        other => Err(enum_error(
            "openstack.address_family",
            other,
            "\"ipv4\", \"ipv6\" or \"any\"",
        )),
    }
}

fn parse_prefer(value: &str) -> std::result::Result<IpPrefer, ConfigError> {
    match value.trim() {
        "floating" => Ok(IpPrefer::Floating),
        "fixed" => Ok(IpPrefer::Fixed),
        "any" => Ok(IpPrefer::Any),
        other => Err(enum_error(
            "openstack.prefer",
            other,
            "\"floating\", \"fixed\" or \"any\"",
        )),
    }
}

fn parse_on_ambiguous(value: &str) -> std::result::Result<OnAmbiguous, ConfigError> {
    match value.trim() {
        "reject" => Ok(OnAmbiguous::Reject),
        "first" => Ok(OnAmbiguous::First),
        other => Err(enum_error(
            "openstack.on_ambiguous",
            other,
            "\"reject\" or \"first\"",
        )),
    }
}

/// Parse `[openstack] route_by`: a non-empty list of `"uuid"` / `"name"`.
///
/// Duplicates are dropped (order preserved, so the log token is stable) and an
/// unknown value names the field. Empty is an error rather than a silent
/// "route nothing": an operator who writes the line wants *some* route.
fn parse_route_by(values: &[String]) -> std::result::Result<Vec<RouteKind>, ConfigError> {
    if values.is_empty() {
        return Err(ConfigError::Invalid {
            field: "openstack.route_by".into(),
            reason: "must list at least one route: \"uuid\" and/or \"name\"".into(),
        });
    }
    let mut out: Vec<RouteKind> = Vec::with_capacity(values.len());
    for value in values {
        let kind = match value.trim() {
            "uuid" => RouteKind::Uuid,
            "name" => RouteKind::Name,
            other => {
                return Err(enum_error(
                    "openstack.route_by",
                    other,
                    "\"uuid\" or \"name\"",
                ));
            }
        };
        if !out.contains(&kind) {
            out.push(kind);
        }
    }
    Ok(out)
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
        assert_eq!(
            cfg.control_plane.as_ref().expect("present").cache_ttl,
            Duration::from_secs(30)
        );
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
    fn the_gateway_holds_no_backend_credential_of_its_own() {
        // plan-agent-only D3: the credential is the end user's forwarded agent,
        // so `BackendConfig` carries nothing key-shaped at all.
        let cfg = GatewayConfig::parse(&minimal_toml()).expect("valid config");
        assert_eq!(cfg.backend.host_key_policy, HostKeyPolicy::Pinned);
        let rendered = format!("{:?}", cfg.backend);
        for removed in [
            "private_key",
            "credential_map",
            "backend_auth",
            "allow_agent_backend_auth",
        ] {
            assert!(
                !rendered.contains(removed),
                "BackendConfig must not mention {removed}: {rendered}"
            );
        }
    }

    #[test]
    fn stale_key_cert_and_jump_style_settings_are_ignored_not_acted_on() {
        // A config file written before agent-only still carries these keys.
        // The parser is permissive, so they parse — but nothing is derived from
        // them: there is no credential to select and no issuing CA to load.
        let toml = minimal_toml()
            .replace(
                "host_key_policy = \"pinned\"",
                "host_key_policy = \"pinned\"\n            backend_auth = \"cert\"\n            credential_map = { root = \"/keys/root_ed\" }\n            allow_agent_backend_auth = true",
            )
            .replace(
                "[control_plane]",
                "[ca]\n            signing_key = \"/keys/ca\"\n            cert_lifetime = \"99s\"\n            [control_plane]",
            );
        let cfg = GatewayConfig::parse(&toml).expect("stale keys must not break the boot");
        assert_eq!(cfg.backend.host_key_policy, HostKeyPolicy::Pinned);
        assert!(cfg.ca.trusted_ca_keys.is_empty());
    }

    #[test]
    fn pool_enabled_is_always_a_config_error() {
        // propose §3.8 tightened to an unconditional rule: the gateway's
        // backend identity is per-session, so there is nothing a shared pooled
        // connection could ever carry.
        let bad = minimal_toml().replace("enabled = false", "enabled = true");
        assert!(bad.contains("enabled = true"), "precondition of the test");
        let err = GatewayConfig::parse(&bad).unwrap_err();
        match err {
            Error::Config(ConfigError::Invalid { field, .. }) => {
                assert_eq!(field, "pool.enabled")
            }
            _ => panic!("expected pool.enabled error, got {err:?}"),
        }
    }

    #[test]
    fn trusted_ca_keys_still_load_verify_only() {
        let toml = minimal_toml().replace(
            "[control_plane]",
            "[ca]\n            trusted_ca_keys = [\"/keys/ca.pub\"]\n            [control_plane]",
        );
        let cfg = GatewayConfig::parse(&toml).expect("verify-only CA is valid");
        assert_eq!(cfg.ca.trusted_ca_keys, vec![PathBuf::from("/keys/ca.pub")]);
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

    // --- [openstack] / instance-UUID routing (plan-openstack §3.6, §4.1) ----

    /// Base config **without** `[control_plane]`, so tests can prove which
    /// routing modes demand a control plane and which do not.
    fn base_without_control_plane() -> String {
        r#"
            [listen]
            addr = "127.0.0.1:2222"

            [host_keys]
            keys = [{ path = "/etc/ssh-gw/host_ed25519", state = "active" }]

            [backend]
            host_key_policy = "pinned"
        "#
        .to_owned()
    }

    /// A valid OpenStack pure-mode section: the lab mode of plan-openstack
    /// §3.5, with every hand-set knob it requires.
    fn openstack_pure_section() -> String {
        r#"
            [openstack]
            enabled = true
            routing = "openstack_only"
            authorization = "openstack_only"
            allow_any_authenticated_key = true
            auth_url = "https://keystone.example.internal:5000/v3"
            application_credential_id = "appcred-id"
            application_credential_secret = "s3cr3t"
            nova_endpoint = "http://127.0.0.1:8774/v2.1"
            default_backend_user = "cloud-user"
        "#
        .to_owned()
    }

    fn parse_err(toml: &str) -> ConfigError {
        match GatewayConfig::parse(toml).unwrap_err() {
            Error::Config(err) => err,
            other => panic!("expected a config error, got {other:?}"),
        }
    }

    fn invalid_field(toml: &str) -> String {
        match parse_err(toml) {
            ConfigError::Invalid { field, .. } => field,
            other => panic!("expected ConfigError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn openstack_is_absent_by_default_and_control_plane_still_required() {
        let cfg = GatewayConfig::parse(&minimal_toml()).expect("valid config");
        assert!(
            cfg.openstack.is_none(),
            "default off = no OpenStack resolver"
        );
        assert!(cfg.control_plane.is_some());

        // No control plane and no OpenStack section at all stays an error —
        // the "control_plane became optional" change is mode-scoped, not a
        // loosening of the existing rule.
        let err = invalid_field(&base_without_control_plane());
        assert_eq!(err, "control_plane");
    }

    #[test]
    fn pure_openstack_mode_needs_no_control_plane() {
        let toml = format!(
            "{}{}",
            base_without_control_plane(),
            openstack_pure_section()
        );
        let cfg =
            GatewayConfig::parse(&toml).expect("pure mode must parse without a control plane");
        assert!(cfg.control_plane.is_none());
        let os = cfg.openstack.expect("openstack configured");
        assert_eq!(os.routing, OpenStackRouting::OpenStackOnly);
        assert_eq!(os.authorization, OpenStackAuthorization::OpenStackOnly);
        assert!(os.allow_any_authenticated_key);
        assert_eq!(os.auth_method, OpenStackAuthMethod::ApplicationCredential);
        assert_eq!(os.application_credential_id, "appcred-id");
        assert_eq!(os.application_credential_secret, "s3cr3t");
        assert_eq!(os.auth_url, "https://keystone.example.internal:5000/v3");
        assert_eq!(os.nova_endpoint, "http://127.0.0.1:8774/v2.1");
        assert_eq!(os.default_backend_user, "cloud-user");
        assert!(os.backend_user_map.is_empty());
        assert!(os.backend_user_metadata_key.is_empty());
        // Documented defaults (plan-openstack §3.6).
        assert_eq!(os.timeout, Duration::from_secs(3));
        assert_eq!(os.cache_ttl, Duration::from_secs(30));
        assert_eq!(os.microversion, "2.1");
        assert_eq!(os.interface, EndpointInterface::Public);
        assert_eq!(os.address_family, AddressFamily::IPv4);
        assert_eq!(os.prefer, IpPrefer::Floating);
        assert_eq!(os.on_ambiguous, OnAmbiguous::Reject);
        // Conservative default: only the UUID route, byte-for-byte the
        // pre-name-routing behaviour (plan-openstack appendix A.1).
        assert_eq!(os.route_by, vec![RouteKind::Uuid]);
        assert_eq!(os.ssh_port, 22);
        assert!(!os.fail_open);
        assert!(os.verify_tls);
        assert!(!os.recording);
    }

    #[test]
    fn pure_mode_still_accepts_an_optional_control_plane() {
        let toml = format!("{}{}", minimal_toml(), openstack_pure_section());
        let cfg = GatewayConfig::parse(&toml).expect("both sections may coexist");
        assert!(cfg.control_plane.is_some(), "an unused CP is tolerated");
        assert!(cfg.openstack.is_some());
    }

    #[test]
    fn route_by_parses_deduplicates_and_preserves_order() {
        let toml = format!(
            "{}\n            route_by = [\"name\", \"uuid\", \"name\"]\n",
            openstack_pure_section()
        );
        let toml = format!("{}{}", base_without_control_plane(), toml);
        let os = GatewayConfig::parse(&toml)
            .expect("valid route_by")
            .openstack
            .expect("openstack");
        assert_eq!(os.route_by, vec![RouteKind::Name, RouteKind::Uuid]);
        // The log token for each kind is stable and lowercase.
        assert_eq!(os.route_by[0].as_str(), "name");
        assert_eq!(os.route_by[1].to_string(), "uuid");
    }

    #[test]
    fn route_by_rejects_unknown_values_and_the_empty_list() {
        let unknown = format!(
            "{}\n            route_by = [\"uuid\", \"bogus\"]\n",
            openstack_pure_section()
        );
        let unknown = format!("{}{}", base_without_control_plane(), unknown);
        assert_eq!(invalid_field(&unknown), "openstack.route_by");

        let empty = format!("{}\n            route_by = []\n", openstack_pure_section());
        let empty = format!("{}{}", base_without_control_plane(), empty);
        assert_eq!(invalid_field(&empty), "openstack.route_by");
    }

    #[test]
    fn route_by_is_still_validated_while_the_feature_is_disabled() {
        // A typo in a line the operator *did* write must fail the boot whether
        // or not the feature is currently on — same rule as `routing`.
        let toml = format!(
            "{}\n            [openstack]\n            enabled = false\n            route_by = [\"nope\"]\n",
            base_without_control_plane()
        );
        assert_eq!(invalid_field(&toml), "openstack.route_by");
    }

    #[test]
    fn non_pure_modes_still_require_a_control_plane() {
        // Section present but disabled: no route exists, so the control plane
        // is still mandatory.
        let toml = format!(
            "{}\n            [openstack]\n            enabled = false\n",
            base_without_control_plane()
        );
        assert_eq!(invalid_field(&toml), "control_plane");
    }

    #[test]
    fn openstack_only_requires_the_danger_flag() {
        let toml = format!(
            "{}{}",
            base_without_control_plane(),
            openstack_pure_section().replace("allow_any_authenticated_key = true\n", "")
        );
        assert_eq!(
            invalid_field(&toml),
            "openstack.allow_any_authenticated_key"
        );
    }

    #[test]
    fn enabled_false_is_an_unconditional_off_switch() {
        // `enabled = false` must switch the section off *no matter what the
        // other fields say*: an operator disabling a resolver should never have
        // to remember to reset `routing`/`authorization` first (the combination
        // rules below only apply while the feature is on).
        let toml = format!(
            "{}{}",
            minimal_toml(),
            openstack_pure_section().replace("enabled = true", "enabled = false")
        );
        let cfg = GatewayConfig::parse(&toml).expect("disabled section parses");
        assert!(
            cfg.openstack.is_none(),
            "the whole [openstack] section must be inert when disabled"
        );

        // Turning it back on is where the combination rules start to bite
        // again, so the off switch cannot be hiding a contradictory config.
        let toml = format!(
            "{}{}",
            minimal_toml(),
            openstack_pure_section()
                .replace("enabled = true", "enabled = false")
                .replace("routing = \"openstack_only\"", "routing = \"hybrid\"")
        );
        let cfg = GatewayConfig::parse(&toml).expect("still disabled");
        assert!(cfg.openstack.is_none());
    }

    #[test]
    fn enum_typos_are_still_caught_while_disabled() {
        // The off switch skips the *combination* rules, never the spellings:
        // a typo should fail at boot instead of silently disabling a resolver.
        let toml = format!(
            "{}{}",
            minimal_toml(),
            openstack_pure_section()
                .replace("enabled = true", "enabled = false")
                .replace("routing = \"openstack_only\"", "routing = \"bogus\"")
        );
        assert_eq!(invalid_field(&toml), "openstack.routing");
    }

    #[test]
    fn authorization_and_routing_must_agree() {
        // openstack_only authorization without an openstack_only route would
        // give the gateway two authorization semantics (plan §3.5 refuses it).
        let toml = format!(
            "{}{}",
            base_without_control_plane(),
            openstack_pure_section()
                .replace("routing = \"openstack_only\"", "routing = \"hybrid\"")
        );
        assert_eq!(invalid_field(&toml), "openstack.routing");

        // The mirror: an openstack_only route with control-plane authorization
        // would advertise an authority that is never consulted.
        let toml = format!(
            "{}{}",
            base_without_control_plane(),
            openstack_pure_section().replace(
                "authorization = \"openstack_only\"",
                "authorization = \"control_plane\""
            )
        );
        assert_eq!(invalid_field(&toml), "openstack.authorization");
    }

    #[test]
    fn hybrid_cannot_be_enabled_without_scheme_a() {
        // `enabled = true` + `routing = "hybrid"` would resolve UUIDs through
        // OpenStack while claiming control-plane authorization; scheme A is not
        // implemented, so the gateway refuses to boot rather than silently
        // authorizing outside the control plane.
        let toml = format!(
            "{}{}",
            minimal_toml(),
            openstack_pure_section()
                .replace("routing = \"openstack_only\"", "routing = \"hybrid\"")
        );
        assert_eq!(invalid_field(&toml), "openstack.routing");
    }

    #[test]
    fn enabled_requires_a_default_backend_user() {
        let toml = format!(
            "{}{}",
            base_without_control_plane(),
            openstack_pure_section().replace("default_backend_user = \"cloud-user\"\n", "")
        );
        assert_eq!(invalid_field(&toml), "openstack.default_backend_user");

        // Whitespace-only is equally useless (§3.4 result validation).
        let toml = format!(
            "{}{}",
            base_without_control_plane(),
            openstack_pure_section().replace(
                "default_backend_user = \"cloud-user\"",
                "default_backend_user = \" \""
            )
        );
        assert_eq!(invalid_field(&toml), "openstack.default_backend_user");
    }

    #[test]
    fn backend_user_must_not_contain_whitespace_or_control_characters() {
        let toml = format!(
            "{}{}",
            base_without_control_plane(),
            openstack_pure_section().replace(
                "default_backend_user = \"cloud-user\"",
                "default_backend_user = \"cloud user\""
            )
        );
        assert_eq!(invalid_field(&toml), "openstack.default_backend_user");
    }

    #[test]
    fn fail_open_requires_a_pinned_host_key() {
        // Red line 5: stale-IP dialing is only safe with host-key pinning.
        let toml = format!(
            "{}{}",
            base_without_control_plane(),
            openstack_pure_section().replace(
                "nova_endpoint = \"http://127.0.0.1:8774/v2.1\"",
                "nova_endpoint = \"http://127.0.0.1:8774/v2.1\"\n            fail_open = true"
            ),
        );
        let unpinned = toml.replace(
            "host_key_policy = \"pinned\"",
            "host_key_policy = \"accept-new\"",
        );
        assert_eq!(invalid_field(&unpinned), "openstack.fail_open");

        // With pinning it is accepted.
        let cfg = GatewayConfig::parse(&toml).expect("pinned + fail_open is valid");
        assert!(cfg.openstack.expect("configured").fail_open);
    }

    #[test]
    fn unknown_enum_values_report_the_offending_field() {
        let cases = [
            ("routing = \"openstack_only\"", "routing = \"bogus\"", "openstack.routing"),
            (
                "authorization = \"openstack_only\"",
                "authorization = \"bogus\"",
                "openstack.authorization",
            ),
            (
                "auth_url = \"https://keystone.example.internal:5000/v3\"",
                "auth_url = \"https://keystone.example.internal:5000/v3\"\n            auth_method = \"password\"",
                "openstack.auth_method",
            ),
            (
                "default_backend_user = \"cloud-user\"",
                "default_backend_user = \"cloud-user\"\n            address_family = \"ip\"",
                "openstack.address_family",
            ),
            (
                "default_backend_user = \"cloud-user\"",
                "default_backend_user = \"cloud-user\"\n            prefer = \"strongest\"",
                "openstack.prefer",
            ),
            (
                "default_backend_user = \"cloud-user\"",
                "default_backend_user = \"cloud-user\"\n            on_ambiguous = \"whatever\"",
                "openstack.on_ambiguous",
            ),
            (
                "default_backend_user = \"cloud-user\"",
                "default_backend_user = \"cloud-user\"\n            interface = \"external\"",
                "openstack.interface",
            ),
        ];
        for (needle, replacement, expected) in cases {
            let toml = format!(
                "{}{}",
                base_without_control_plane(),
                openstack_pure_section().replace(needle, replacement)
            );
            assert_eq!(invalid_field(&toml), expected, "replacing {needle:?}");
        }
    }

    #[test]
    fn enum_typos_are_caught_even_while_the_feature_is_disabled() {
        // A landmine left in a disabled section must fail at boot, not on the
        // first UUID that ever arrives.
        let toml = format!(
            "{}\n            [openstack]\n            enabled = false\n            routing = \"alĺ hybrids\"\n",
            minimal_toml()
        );
        assert_eq!(invalid_field(&toml), "openstack.routing");
    }

    #[test]
    fn missing_credentials_report_the_field_that_would_fix_them() {
        let no_secret =
            openstack_pure_section().replace("application_credential_secret = \"s3cr3t\"\n", "");
        assert_eq!(
            invalid_field(&format!("{}{no_secret}", base_without_control_plane())),
            "openstack.application_credential_secret"
        );

        let no_id =
            openstack_pure_section().replace("application_credential_id = \"appcred-id\"\n", "");
        assert_eq!(
            invalid_field(&format!("{}{no_id}", base_without_control_plane())),
            "openstack.application_credential_id"
        );

        // auth_method = token swaps which credential is demanded.
        let token_mode = openstack_pure_section()
            .replace("application_credential_id = \"appcred-id\"\n", "")
            .replace(
                "application_credential_secret = \"s3cr3t\"",
                "auth_method = \"token\"",
            );
        assert_eq!(
            invalid_field(&format!("{}{token_mode}", base_without_control_plane())),
            "openstack.token"
        );
    }

    #[test]
    fn secret_resolution_prefers_file_then_literal_then_environment() {
        let env = Some("from-env");
        assert_eq!(
            resolve_secret("f", "", "from-literal", env).unwrap(),
            "from-literal"
        );
        assert_eq!(resolve_secret("f", "", "", env).unwrap(), "from-env");
        assert_eq!(resolve_secret("f", "", "", None).unwrap(), "");

        // A file wins over both, with the trailing newline editors add removed.
        let dir = std::env::temp_dir().join(format!("sshgw-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("secret.txt");
        std::fs::write(&path, "file-secret\n").expect("write secret");
        let resolved = resolve_secret("f", path.to_str().unwrap(), "from-literal", env).unwrap();
        assert_eq!(resolved, "file-secret");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_secret_file_is_an_error_not_a_fallback() {
        let dir = std::env::temp_dir().join(format!("sshgw-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("empty.txt");
        std::fs::write(&path, "\n").expect("write empty secret");
        let err = resolve_secret(
            "openstack.application_credential_secret_file",
            path.to_str().unwrap(),
            "from-literal",
            None,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("openstack.application_credential_secret_file: secret file {path:?} is empty")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secrets_never_appear_in_debug_output() {
        let toml = format!("{}{}", minimal_toml(), openstack_pure_section());
        let cfg = GatewayConfig::parse(&toml).expect("valid config");
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("s3cr3t"), "secret leaked: {rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn absolute_urls_are_required_for_keystone_and_nova() {
        let bad = openstack_pure_section().replace(
            "auth_url = \"https://keystone.example.internal:5000/v3\"",
            "auth_url = \"keystone.internal:5000/v3\"",
        );
        assert_eq!(
            invalid_field(&format!("{}{bad}", base_without_control_plane())),
            "openstack.auth_url"
        );

        let bad = openstack_pure_section().replace(
            "nova_endpoint = \"http://127.0.0.1:8774/v2.1\"",
            "nova_endpoint = \"nova.internal:8774\"",
        );
        assert_eq!(
            invalid_field(&format!("{}{bad}", base_without_control_plane())),
            "openstack.nova_endpoint"
        );
    }

    #[test]
    fn zero_timeouts_and_ports_are_rejected() {
        let bad = openstack_pure_section().replace(
            "default_backend_user = \"cloud-user\"",
            "default_backend_user = \"cloud-user\"\n            timeout = \"0s\"",
        );
        assert_eq!(
            invalid_field(&format!("{}{bad}", base_without_control_plane())),
            "openstack.timeout"
        );

        let bad = openstack_pure_section().replace(
            "default_backend_user = \"cloud-user\"",
            "default_backend_user = \"cloud-user\"\n            cache_ttl = \"0s\"",
        );
        assert_eq!(
            invalid_field(&format!("{}{bad}", base_without_control_plane())),
            "openstack.cache_ttl"
        );

        let bad = openstack_pure_section().replace(
            "default_backend_user = \"cloud-user\"",
            "default_backend_user = \"cloud-user\"\n            ssh_port = 0",
        );
        assert_eq!(
            invalid_field(&format!("{}{bad}", base_without_control_plane())),
            "openstack.ssh_port"
        );
    }

    #[test]
    fn backend_user_rules_are_parsed_and_validated() {
        let rules = r#"
            [[openstack.backend_user_map]]
            match_name = "^web-"
            match_metadata = { role = "web" }
            user = "ubuntu"

            [[openstack.backend_user_map]]
            match_metadata = { tier = "db" }
            user = "postgres"
        "#;
        let toml = format!(
            "{}{}{rules}",
            base_without_control_plane(),
            openstack_pure_section()
        );
        let cfg = GatewayConfig::parse(&toml).expect("rules are valid");
        let os = cfg.openstack.expect("configured");
        assert_eq!(os.backend_user_map.len(), 2);
        assert_eq!(os.backend_user_map[0].match_name, "^web-");
        assert_eq!(os.backend_user_map[0].user, "ubuntu");
        assert_eq!(
            os.backend_user_map[0]
                .match_metadata
                .get("role")
                .map(String::as_str),
            Some("web")
        );
        assert!(os.backend_user_map[1].match_name.is_empty());
        assert_eq!(os.backend_user_map[1].user, "postgres");
    }

    #[test]
    fn unconditional_or_nonsense_rules_are_rejected() {
        let unconditional = r#"
            [[openstack.backend_user_map]]
            user = "ubuntu"
        "#;
        let toml = format!(
            "{}{}{unconditional}",
            base_without_control_plane(),
            openstack_pure_section()
        );
        assert_eq!(invalid_field(&toml), "openstack.backend_user_map[0]");

        // A rule with no usable user would silently break every login it wins.
        let no_user = r#"
            [[openstack.backend_user_map]]
            match_name = "^web-"
            user = ""
        "#;
        let toml = format!(
            "{}{}{no_user}",
            base_without_control_plane(),
            openstack_pure_section()
        );
        assert_eq!(invalid_field(&toml), "openstack.backend_user_map[0].user");

        // Regex is not implemented in v1: reject rather than match literally.
        let regex = r#"
            [[openstack.backend_user_map]]
            match_name = "^web-.*"
            user = "ubuntu"
        "#;
        let toml = format!(
            "{}{}{regex}",
            base_without_control_plane(),
            openstack_pure_section()
        );
        assert_eq!(
            invalid_field(&toml),
            "openstack.backend_user_map[0].match_name"
        );
    }

    #[test]
    fn static_token_auth_needs_an_explicit_nova_endpoint() {
        // No catalog is available without a Keystone exchange, so the endpoint
        // cannot be discovered later — reject at boot instead.
        let toml = format!(
            "{}{}",
            base_without_control_plane(),
            openstack_pure_section()
                .replace("nova_endpoint = \"http://127.0.0.1:8774/v2.1\"\n", "")
                .replace(
                    "application_credential_secret = \"s3cr3t\"",
                    "auth_method = \"token\"\n            token = \"static\""
                )
        );
        assert_eq!(invalid_field(&toml), "openstack.nova_endpoint");
    }

    #[test]
    fn shipped_example_config_still_parses() {
        // The optional-`control_plane` refactor must not loosen anything the
        // shipped sample relies on: it has no `[openstack]` section, so it
        // still needs its control plane and must come out unchanged.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
        let text = std::fs::read_to_string(&path).expect("example config exists");
        let cfg = GatewayConfig::parse(&text).expect("config.example.toml must stay valid");
        assert!(cfg.openstack.is_none());
        assert!(cfg.control_plane.is_some());
    }
}
