//! OpenStack access for instance-UUID routing (plan-openstack §3.2).
//!
//! [`OpenStackClient`] implements [`ControlPlaneClient`], so the resolver's
//! cache, single-flight, negative TTL and circuit breaker are reused unchanged
//! and the OpenStack route gets its **own** `Resolver` instance — a dead
//! Keystone must not open the control plane's breaker (plan-openstack §0-3).
//!
//! Responsibilities:
//! * Keystone v3 token acquisition (application credential, or a static token
//!   escape hatch for tests) with caching until `expires_at` minus a skew, and
//!   invalidation + one re-fetch when Nova answers 401;
//! * Nova `GET /v2.1/servers/{uuid}` with the configured microversion;
//! * address selection and backend-login-user mapping, which are pure functions
//!   in [`nova`];
//! * failure mapping onto [`ControlError`] so every refusal is **identical**
//!   from the client's point of view (no UUID existence oracle).
//!
//! Security invariants enforced here:
//! * the username is used *only* as the Nova path segment, and only after being
//!   re-checked as a canonical UUID — no host, no path, no query ever comes from
//!   the client (plan-openstack §3.5 red line 3, SSRF);
//! * no secret, token or URL credential is ever logged.

pub mod nova;

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::config::{EndpointInterface, OpenStackAuthMethod, OpenStackConfig};
use crate::resolve::ControlError;
use crate::types::{is_instance_uuid, Policy, ResolveRequest, ResolveResponse, Target};

use nova::{
    map_backend_user, select_address, AddressSelection, NovaServer, UserMapping, UserSource,
};

/// Refresh a token this long before its advertised expiry: a token that dies
/// mid-request would cost a pointless 401 round trip.
const TOKEN_SKEW: Duration = Duration::from_secs(60);

/// Failures that happen while *building* the client are startup-fatal: the
/// gateway must not come up with an OpenStack route it cannot talk to.
#[derive(Debug, thiserror::Error)]
pub enum OpenStackInitError {
    #[error("failed to read openstack.ca_bundle {path:?}: {source}")]
    ReadCaBundle {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("openstack.ca_bundle {path:?} is not a valid PEM certificate: {source}")]
    ParseCaBundle {
        path: std::path::PathBuf,
        #[source]
        source: reqwest::Error,
    },

    #[error("failed to build the OpenStack HTTP client: {0}")]
    Client(#[source] reqwest::Error),
}

/// One Keystone token plus everything derived from it.
#[derive(Debug, Clone)]
struct CachedToken {
    value: String,
    /// `None` when the issuer gave no parseable expiry (or the auth method is a
    /// static token): the token is then kept until Nova rejects it with 401.
    expires_at: Option<SystemTime>,
    /// Resolved Nova base URL (config override or service catalog).
    nova_base: String,
}

/// Keystone `POST /v3/auth/tokens` response body (the parts we use).
#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: TokenBody,
}

#[derive(Debug, Deserialize)]
struct TokenBody {
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    catalog: Vec<CatalogService>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CatalogService {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub region_id: Option<String>,
    #[serde(default)]
    pub endpoints: Vec<CatalogEndpoint>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CatalogEndpoint {
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub region_id: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

/// A Keystone/Nova client for one configured cloud.
pub struct OpenStackClient {
    cfg: OpenStackConfig,
    http: reqwest::Client,
    token: Mutex<Option<CachedToken>>,
}

impl OpenStackClient {
    /// Build the client. Startup-fatal warnings are emitted here so an operator
    /// sees every dangerous setting once, at boot (plan-openstack §3.5 / §3.6).
    pub fn new(cfg: OpenStackConfig) -> Result<Self, OpenStackInitError> {
        if cfg.allow_any_authenticated_key {
            tracing::warn!(
                target: "openstack",
                "openstack.allow_any_authenticated_key = true: any key that passes front-leg \
                 verification can reach any instance UUID it knows. Lab mode only."
            );
        }
        if !cfg.verify_tls {
            tracing::warn!(
                target: "openstack",
                "openstack.verify_tls = false: Keystone/Nova certificates are not verified"
            );
        }
        for (field, url) in [
            ("openstack.auth_url", cfg.auth_url.as_str()),
            ("openstack.nova_endpoint", cfg.nova_endpoint.as_str()),
        ] {
            if url.starts_with("http://") {
                tracing::warn!(
                    target: "openstack",
                    %field,
                    %url,
                    "talking to OpenStack over plain http: tokens and addresses are exposed \
                     on the wire"
                );
            }
        }
        if cfg.fail_open {
            tracing::warn!(
                target: "openstack",
                "openstack.fail_open = true: a stale instance address will be dialed when \
                 Nova is unreachable (requires [backend] host_key_policy = \"pinned\")"
            );
        }

        let mut builder = reqwest::Client::builder().timeout(cfg.timeout);
        if !cfg.verify_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if !cfg.ca_bundle.as_os_str().is_empty() {
            let path = cfg.ca_bundle.clone();
            let pem = std::fs::read(&path).map_err(|source| OpenStackInitError::ReadCaBundle {
                path: path.clone(),
                source,
            })?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|source| OpenStackInitError::ParseCaBundle { path, source })?;
            builder = builder.add_root_certificate(cert);
        }
        let http = builder.build().map_err(OpenStackInitError::Client)?;

        Ok(OpenStackClient {
            cfg,
            http,
            token: Mutex::new(None),
        })
    }

    // --- token lifecycle ---------------------------------------------------

    fn lock(&self) -> MutexGuard<'_, Option<CachedToken>> {
        // A poisoned lock only means a panic elsewhere; we store plain data.
        self.token.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn cached_valid(&self) -> Option<CachedToken> {
        let guard = self.lock();
        let cached = guard.as_ref()?;
        match cached.expires_at {
            Some(expires) if expires <= SystemTime::now() + TOKEN_SKEW => None,
            _ => Some(cached.clone()),
        }
    }

    fn invalidate_token(&self) {
        *self.lock() = None;
    }

    /// A usable token + Nova base URL, from cache when still valid.
    async fn acquire(&self) -> Result<CachedToken, ControlError> {
        match self.cfg.auth_method {
            // Static-token escape hatch: no Keystone round trip, and the config
            // already required a `nova_endpoint` (there is no catalog to read).
            OpenStackAuthMethod::Token => Ok(CachedToken {
                value: self.cfg.token.clone(),
                expires_at: None,
                nova_base: self.cfg.nova_endpoint.trim_end_matches('/').to_owned(),
            }),
            OpenStackAuthMethod::ApplicationCredential => {
                if let Some(cached) = self.cached_valid() {
                    return Ok(cached);
                }
                let fresh = self.fetch_token().await?;
                *self.lock() = Some(fresh.clone());
                Ok(fresh)
            }
        }
    }

    /// `POST {auth_url}/auth/tokens`.
    async fn fetch_token(&self) -> Result<CachedToken, ControlError> {
        let url = format!("{}/auth/tokens", self.cfg.auth_url.trim_end_matches('/'));
        let body = self.auth_body();
        let resp = self.send(|| self.http.post(&url).json(&body)).await?;

        match resp.status().as_u16() {
            200 | 201 => {
                let subject = resp
                    .headers()
                    .get("x-subject-token")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let Some(subject) = subject else {
                    tracing::warn!(
                        target: "openstack",
                        reason = "no_subject_token",
                        "Keystone answered without an X-Subject-Token header"
                    );
                    return Err(ControlError::Decode);
                };
                let parsed: TokenResponse = match resp.json().await {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        tracing::warn!(
                            target: "openstack",
                            reason = "decode",
                            "Keystone token response could not be decoded"
                        );
                        return Err(ControlError::Decode);
                    }
                };
                let expires_at = parsed
                    .token
                    .expires_at
                    .as_deref()
                    .and_then(parse_rfc3339_utc);
                if parsed.token.expires_at.is_some() && expires_at.is_none() {
                    tracing::warn!(
                        target: "openstack",
                        reason = "expiry_unparseable",
                        "Keystone expires_at could not be parsed; the token will be kept \
                         until Nova rejects it with 401"
                    );
                }
                let nova_base = nova_base_from_catalog(&self.cfg, &parsed.token.catalog)?;
                Ok(CachedToken {
                    value: subject,
                    expires_at,
                    nova_base,
                })
            }
            401 | 403 => {
                tracing::warn!(
                    target: "openstack",
                    reason = "forbidden",
                    status = resp.status().as_u16(),
                    "Keystone refused the application credential"
                );
                Err(ControlError::Forbidden)
            }
            429 => Err(ControlError::RateLimited),
            status if (500..=599).contains(&status) => {
                tracing::warn!(
                    target: "openstack",
                    reason = "keystone_5xx",
                    status,
                    "Keystone is unhealthy"
                );
                Err(ControlError::ServerError)
            }
            status => {
                tracing::warn!(
                    target: "openstack",
                    reason = "unexpected_status",
                    status,
                    "unexpected Keystone status"
                );
                Err(ControlError::ServerError)
            }
        }
    }

    fn auth_body(&self) -> serde_json::Value {
        match self.cfg.auth_method {
            OpenStackAuthMethod::Token => serde_json::json!({
                "auth": { "identity": { "methods": ["token"], "token": { "value": self.cfg.token } } }
            }),
            OpenStackAuthMethod::ApplicationCredential => {
                let identity = serde_json::json!({
                    "methods": ["application_credential"],
                    "application_credential": {
                        "id": self.cfg.application_credential_id,
                        "secret": self.cfg.application_credential_secret,
                    }
                });
                let mut auth = serde_json::json!({ "identity": identity });
                // `scope` sits beside `identity` (Keystone v3 shape). It is the
                // blast-radius gate that limits which instances this gateway can
                // even see, so it is sent whenever it is configured.
                if !self.cfg.project_id.is_empty() {
                    auth["scope"] = serde_json::json!({ "project": { "id": self.cfg.project_id } });
                }
                serde_json::json!({ "auth": auth })
            }
        }
    }

    // --- Nova --------------------------------------------------------------

    /// `GET {nova}/servers/{uuid}`, retrying a single 401 with a fresh token.
    async fn get_server(
        &self,
        mut token: CachedToken,
        uuid: &str,
    ) -> Result<NovaServer, ControlError> {
        let mut refreshed = false;
        loop {
            let url = format!("{}/servers/{}", token.nova_base, uuid);
            let microversion = self.cfg.microversion.as_str();
            let resp = self
                .send(|| {
                    self.http
                        .get(&url)
                        .header("X-Auth-Token", token.value.as_str())
                        .header("OpenStack-API-Version", format!("compute {microversion}"))
                        .header("X-OpenStack-Nova-API-Version", microversion)
                })
                .await?;

            let status = resp.status().as_u16();
            if status == 401 && !refreshed {
                // The cached token died under us: drop it, take a new one, and
                // try exactly once more (plan-openstack §3.2).
                tracing::debug!(target: "openstack", reason = "token_expired", %uuid,
                    "Nova rejected the cached token; refreshing");
                self.invalidate_token();
                token = self.acquire().await?;
                refreshed = true;
                continue;
            }

            return match status {
                200 => match resp.json().await {
                    Ok(server) => Ok(server),
                    Err(_) => {
                        tracing::warn!(
                            target: "openstack",
                            reason = "decode",
                            %uuid,
                            "Nova server response could not be decoded"
                        );
                        Err(ControlError::Decode)
                    }
                },
                404 => {
                    tracing::warn!(
                        target: "openstack",
                        reason = "not_found",
                        %uuid,
                        "no such instance (or not visible to this application credential)"
                    );
                    Err(ControlError::NotFound)
                }
                401 | 403 => {
                    tracing::warn!(
                        target: "openstack",
                        reason = "forbidden",
                        %uuid,
                        status,
                        "Nova refused the token"
                    );
                    Err(ControlError::Forbidden)
                }
                429 => Err(ControlError::RateLimited),
                status if (500..=599).contains(&status) => {
                    tracing::warn!(
                        target: "openstack",
                        reason = "nova_5xx",
                        %uuid,
                        status,
                        "Nova is unhealthy"
                    );
                    Err(ControlError::ServerError)
                }
                status => {
                    tracing::warn!(
                        target: "openstack",
                        reason = "unexpected_status",
                        %uuid,
                        status,
                        "unexpected Nova status"
                    );
                    Err(ControlError::ServerError)
                }
            };
        }
    }

    /// Send `make()`, retrying a **single connect failure** (DNS / TCP refused).
    ///
    /// Never retries a timeout or a request that may already have reached the
    /// server: an unbounded retry loop turns a slow cloud into an amplifier
    /// (plan-openstack §3.2). Repeated failures are the breaker's job.
    async fn send(
        &self,
        make: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, ControlError> {
        let mut attempts = 0u8;
        loop {
            match make().send().await {
                Ok(resp) => return Ok(resp),
                Err(err) if err.is_connect() && attempts == 0 => {
                    tracing::debug!(target: "openstack", reason = "connect_retry",
                        "connect failed; retrying once");
                    attempts += 1;
                }
                Err(err) => {
                    tracing::warn!(
                        target: "openstack",
                        reason = "transport",
                        error = %err,
                        "OpenStack request failed"
                    );
                    return Err(ControlError::Transport);
                }
            }
        }
    }
}

impl crate::resolve::ControlPlaneClient for OpenStackClient {
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

impl OpenStackClient {
    async fn resolve_inner(
        &self,
        req: &ResolveRequest,
    ) -> std::result::Result<ResolveResponse, ControlError> {
        let uuid = req.principal.as_str();

        // Defence in depth (plan-openstack §3.5 red line 3): this string is the
        // *only* thing appended to the Nova base URL, so it must be a canonical
        // UUID — never a host, a path segment or a query. Rejecting here means
        // even a wiring mistake upstream cannot turn the gateway into an SSRF
        // proxy.
        if !is_instance_uuid(uuid) {
            tracing::warn!(
                target: "openstack",
                principal = uuid,
                client_ip = %req.client_ip,
                reason = "not_a_uuid",
                "refusing to query Nova for a non-UUID principal"
            );
            return Err(ControlError::NotFound);
        }
        tracing::debug!(
            target: "openstack",
            %uuid,
            client_ip = %req.client_ip,
            key_fp = %req.key_fp,
            "resolving instance address"
        );

        let token = self.acquire().await?;
        let server = self.get_server(token, uuid).await?;

        let selection = AddressSelection {
            network: &self.cfg.network,
            family: self.cfg.address_family,
            prefer: self.cfg.prefer,
            on_ambiguous: self.cfg.on_ambiguous,
        };
        let access_ips = server.access_ips();
        let addr = select_address(&server.addresses, &access_ips, &selection).map_err(|err| {
            tracing::warn!(
                target: "openstack",
                %uuid,
                reason = err.reason(),
                "instance address could not be selected"
            );
            // Identical to "unknown instance" from the outside: a client must
            // not be able to tell why the lookup failed.
            ControlError::NotFound
        })?;

        let name = server.name.as_deref().unwrap_or("");
        let choice = map_backend_user(
            &server.metadata,
            name,
            &UserMapping {
                metadata_key: &self.cfg.backend_user_metadata_key,
                rules: &self.cfg.backend_user_map,
                default: &self.cfg.default_backend_user,
            },
        );
        if let Some(rejected) = &choice.rejected_metadata {
            tracing::warn!(
                target: "openstack",
                %uuid,
                reason = "user_map",
                value = %rejected,
                "instance metadata carries an unusable backend login user; \
                 falling through to the configured mapping"
            );
        }
        tracing::debug!(
            target: "openstack",
            %uuid,
            %addr,
            user = %choice.user,
            source = choice.source.as_str(),
            instance_name = name,
            "instance address resolved"
        );
        if choice.source == UserSource::Default && self.cfg.default_backend_user.is_empty() {
            // Unreachable: `default_backend_user` is required at config time.
            return Err(ControlError::Decode);
        }

        Ok(ResolveResponse {
            target: Target {
                host: addr.to_string(),
                port: self.cfg.ssh_port,
                user: choice.user,
            },
            policy: Policy {
                // Hard requirement (plan-openstack §0-6): the gateway holds no
                // backend credential of its own, so agent forwarding is the only
                // way this grant can ever open a session.
                agent_forwarding: true,
                recording: self.cfg.recording,
                ttl: u32::try_from(self.cfg.cache_ttl.as_secs()).unwrap_or(u32::MAX),
            },
        })
    }
}

/// Pick the Nova base URL from an explicit override or the service catalog
/// (plan-openstack §3.2).
///
/// Selection: `service.type == "compute"`, matching `interface`, matching
/// `region` when one is configured. With no region configured the first match
/// wins and a warning is emitted, because "first" is arbitrary on a multi
/// region cloud.
pub fn nova_base_from_catalog(
    cfg: &OpenStackConfig,
    catalog: &[CatalogService],
) -> Result<String, ControlError> {
    if !cfg.nova_endpoint.is_empty() {
        return Ok(cfg.nova_endpoint.trim_end_matches('/').to_owned());
    }

    let service = catalog
        .iter()
        .find(|svc| svc.kind.as_deref() == Some("compute"));
    let Some(service) = service else {
        tracing::warn!(
            target: "openstack",
            reason = "no_compute_endpoint",
            "the service catalog has no compute service"
        );
        return Err(ControlError::ServerError);
    };

    let want_interface = match cfg.interface {
        EndpointInterface::Public => "public",
        EndpointInterface::Internal => "internal",
        EndpointInterface::Admin => "admin",
    };
    let region = cfg.region.as_str();

    let mut matches: Vec<&CatalogEndpoint> = service
        .endpoints
        .iter()
        .filter(|ep| ep.interface.as_deref() == Some(want_interface) && ep.url.is_some())
        .filter(|ep| {
            if region.is_empty() {
                return true;
            }
            let ep_region = ep
                .region
                .as_deref()
                .or(ep.region_id.as_deref())
                .or(service.region.as_deref())
                .or(service.region_id.as_deref());
            ep_region == Some(region)
        })
        .collect();

    if matches.is_empty() {
        tracing::warn!(
            target: "openstack",
            reason = "no_compute_endpoint",
            interface = want_interface,
            region,
            "no matching compute endpoint in the service catalog"
        );
        return Err(ControlError::ServerError);
    }

    if region.is_empty() && matches.len() > 1 {
        tracing::warn!(
            target: "openstack",
            reason = "region_unspecified",
            "openstack.region is empty; using the first compute endpoint"
        );
    }
    // Deterministic: catalogs are order-stable, and ties were warned about.
    let url = matches.remove(0).url.as_deref().unwrap_or_default();
    Ok(url.trim_end_matches('/').to_owned())
}

/// Parse the RFC 3339 timestamps Keystone emits (`2026-10-14T18:23:45.123456Z`)
/// without pulling in a date crate. Returns `None` for anything it does not
/// fully understand, which is safe: the token is then kept until Nova says 401.
pub fn parse_rfc3339_utc(raw: &str) -> Option<SystemTime> {
    let b = raw.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b't') {
        return None;
    }
    let year: i64 = raw.get(0..4)?.parse().ok()?;
    let month: i64 = raw.get(5..7)?.parse().ok()?;
    let day: i64 = raw.get(8..10)?.parse().ok()?;
    let hour: i64 = raw.get(11..13)?.parse().ok()?;
    let minute: i64 = raw.get(14..16)?.parse().ok()?;
    let second: i64 = raw.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut idx = 19;
    if b.get(idx) == Some(&b'.') {
        idx += 1;
        let start = idx;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == start {
            return None;
        }
    }

    let tail = raw.get(idx..)?;
    let offset = match tail {
        "Z" | "z" | "+00:00" | "-00:00" => 0,
        _ => {
            let t = tail.as_bytes();
            if t.len() != 6 || t[3] != b':' {
                return None;
            }
            let sign = match t[0] {
                b'+' => 1i64,
                b'-' => -1i64,
                _ => return None,
            };
            let oh: i64 = tail.get(1..3)?.parse().ok()?;
            let om: i64 = tail.get(4..6)?.parse().ok()?;
            if oh > 23 || om > 59 {
                return None;
            }
            sign * (oh * 3600 + om * 60)
        }
    };

    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    if secs < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`), kept local to avoid a date dependency.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::nova::SelectionError;
    use super::*;
    use crate::config::GatewayConfig;
    // The trait is what `OpenStackClient::resolve` is reached through in
    // production; importing it here keeps the tests on the same path.
    use crate::resolve::ControlPlaneClient;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex, OnceLock};

    const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

    // ------------------------------------------------------------------
    // A minimal HTTP server: enough to drive the real reqwest client
    // without adding a test-only dependency.
    // ------------------------------------------------------------------

    #[derive(Debug, Clone)]
    struct Request {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Request {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    struct Response {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Response {
        fn json(status: u16, body: &str) -> Self {
            Response {
                status,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: body.to_owned(),
            }
        }
        /// A Keystone token response: 201 + `X-Subject-Token` + JSON body.
        fn token(subject: &str, body: &str) -> Self {
            let mut response = Response::json(201, body);
            response
                .headers
                .push(("X-Subject-Token".into(), subject.to_owned()));
            response
        }
        fn empty(status: u16) -> Self {
            Response {
                status,
                headers: Vec::new(),
                body: String::new(),
            }
        }
    }

    fn reason(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Status",
        }
    }

    struct MockHttp {
        addr: SocketAddr,
        requests: Arc<Mutex<Vec<Request>>>,
    }

    impl MockHttp {
        fn start<F>(handler: F) -> Self
        where
            F: Fn(&Request) -> Response + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock http");
            let addr = listener.local_addr().expect("mock addr");
            let requests: Arc<Mutex<Vec<Request>>> = Arc::default();
            let recorded = Arc::clone(&requests);
            let handler = Arc::new(handler);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { break };
                    let _ = serve_one(stream, &*handler, &recorded);
                }
            });
            MockHttp { addr, requests }
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{}", self.addr, path)
        }

        fn requests(&self) -> Vec<Request> {
            self.requests.lock().expect("lock").clone()
        }

        fn count(&self, path: &str) -> usize {
            self.requests().iter().filter(|r| r.path == path).count()
        }
    }

    fn find(bytes: &[u8], needle: &[u8]) -> Option<usize> {
        bytes.windows(needle.len()).position(|w| w == needle)
    }

    fn serve_one(
        mut stream: TcpStream,
        handler: &dyn Fn(&Request) -> Response,
        recorded: &Mutex<Vec<Request>>,
    ) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut buf = Vec::new();
        let header_end = loop {
            if let Some(pos) = find(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > 64 * 1024 {
                return Ok(());
            }
            let mut chunk = [0u8; 2048];
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        };

        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_uppercase();
        let path = parts.next().unwrap_or_default().to_string();

        let mut headers = Vec::new();
        let mut content_length = 0usize;
        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_owned();
                let value = value.trim().to_owned();
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap_or(0);
                }
                headers.push((key, value));
            }
        }

        let mut body = buf[header_end..].to_vec();
        while body.len() < content_length {
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }

        let request = Request {
            method,
            path,
            headers,
            body: String::from_utf8_lossy(&body).to_string(),
        };
        if let Ok(mut guard) = recorded.lock() {
            guard.push(request.clone());
        }
        let response = handler(&request);

        let mut out = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            response.status,
            reason(response.status),
            response.body.len()
        );
        for (key, value) in &response.headers {
            out.push_str(&format!("{key}: {value}\r\n"));
        }
        out.push_str("\r\n");
        out.push_str(&response.body);
        stream.write_all(out.as_bytes())?;
        stream.flush()?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Config + fixture helpers.
    // ------------------------------------------------------------------

    /// The `auth_url` / `nova_endpoint` pair pointing at mock HTTP server
    /// `base`, for use as `os_config`'s `extra`.
    fn urls(base: &str) -> String {
        format!("auth_url = \"{base}/v3\"\nnova_endpoint = \"{base}/v2.1\"")
    }

    /// A valid pure-mode `[openstack]` section.
    ///
    /// `extra` supplies the endpoints (see [`urls`]) plus whatever the test
    /// varies; it is spliced verbatim, so it must not repeat a key the template
    /// already sets.
    fn os_config(extra: &str) -> OpenStackConfig {
        let text = format!(
            r#"
            [listen]
            addr = "127.0.0.1:2222"

            [host_keys]
            keys = [{{ path = "/etc/ssh-gw/host_ed25519" }}]

            [backend]
            host_key_policy = "pinned"

            [openstack]
            enabled = true
            routing = "openstack_only"
            authorization = "openstack_only"
            allow_any_authenticated_key = true
            application_credential_id = "cred-id"
            application_credential_secret = "cred-secret"
            default_backend_user = "cloud-user"
            {extra}
            "#
        );
        GatewayConfig::parse(&text)
            .expect("test config parses")
            .openstack
            .expect("openstack section")
    }

    fn token_body(expires_at: &str, base: &str) -> String {
        format!(
            r#"{{"token":{{"expires_at":"{expires_at}","catalog":[
                {{"type":"compute","region":"RegionOne","endpoints":[
                    {{"interface":"public","region":"RegionOne","url":"{base}/v2.1"}}
                ]}}
            ]}}}}"#
        )
    }

    fn server_json(addresses: &str) -> String {
        format!(
            r#"{{"id":"{UUID}","name":"web-1","addresses":{addresses},
               "metadata":{{"iris_ssh_user":"alice"}},
               "image":{{"id":"img-1"}}}}"#
        )
    }

    fn req(principal: &str) -> ResolveRequest {
        ResolveRequest {
            principal: principal.to_owned(),
            client_ip: "198.51.100.9".to_owned(),
            key_fp: "SHA256:fp".to_owned(),
        }
    }

    /// A mock that issues tokens and serves one instance with a single address.
    fn keystone_and_nova(expires_at: String) -> (MockHttp, Arc<OnceLock<String>>) {
        let base = Arc::new(OnceLock::<String>::new());
        let base_for_handler = Arc::clone(&base);
        let server = MockHttp::start(move |request| {
            let base = base_for_handler.get().cloned().unwrap_or_default();
            match (request.method.as_str(), request.path.as_str()) {
                ("POST", "/v3/auth/tokens") => {
                    Response::token("subject-token", &token_body(&expires_at, &base))
                }
                ("GET", path) if path.starts_with("/v2.1/servers/") => Response::json(
                    200,
                    &server_json(
                        r#"{"private":[{"addr":"10.0.0.7","version":4,"OS-EXT-IPS:type":"fixed"}]}"#,
                    ),
                ),
                _ => Response::json(404, "{}"),
            }
        });
        base.set(server.url("")).expect("base url set");
        (server, base)
    }

    // ------------------------------------------------------------------
    // Tests.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn full_flow_resolves_ip_user_and_policy() {
        let (mock, base) = keystone_and_nova("2099-01-01T00:00:00.000000Z".to_owned());
        let base = base.get().expect("base").clone();
        let cfg = os_config(&format!(
            "{}\nbackend_user_metadata_key = \"iris_ssh_user\"\nproject_id = \"proj-1\"",
            urls(&base)
        ));
        let client = OpenStackClient::new(cfg).expect("client");

        let grant = client.resolve(&req(UUID)).await.expect("resolves");

        assert_eq!(grant.target.host, "10.0.0.7");
        assert_eq!(grant.target.port, 22);
        assert_eq!(grant.target.user, "alice", "metadata wins the user mapping");
        assert!(
            grant.policy.agent_forwarding,
            "red line: agent forwarding is on"
        );
        assert!(!grant.policy.recording);
        assert_eq!(
            grant.policy.ttl, 30,
            "policy.ttl mirrors openstack.cache_ttl"
        );

        // Keystone once, Nova once, with the right auth/microversion headers.
        let requests = mock.requests();
        assert_eq!(requests.len(), 2);
        let keystone = &requests[0];
        assert_eq!(keystone.path, "/v3/auth/tokens");
        assert!(keystone.body.contains("application_credential"));
        assert!(keystone.body.contains("cred-secret"));
        assert!(
            keystone.body.contains("\"scope\""),
            "project scope is sent: {}",
            keystone.body
        );
        assert!(keystone.body.contains("proj-1"));

        let nova = &requests[1];
        assert_eq!(nova.path, format!("/v2.1/servers/{UUID}"));
        assert!(!nova.header("X-Auth-Token").unwrap().is_empty());
        assert_eq!(nova.header("OpenStack-API-Version"), Some("compute 2.1"));
        assert_eq!(nova.header("X-OpenStack-Nova-API-Version"), Some("2.1"));
    }

    #[tokio::test]
    async fn token_is_cached_across_lookups() {
        let (mock, base) = keystone_and_nova("2099-01-01T00:00:00.000000Z".to_owned());
        let base = base.get().expect("base").clone();
        let cfg = os_config(&urls(&base));
        let client = OpenStackClient::new(cfg).expect("client");

        client.resolve(&req(UUID)).await.expect("first");
        client.resolve(&req(UUID)).await.expect("second");

        assert_eq!(mock.count("/v3/auth/tokens"), 1, "token reused");
        assert_eq!(mock.count(&format!("/v2.1/servers/{UUID}")), 2);
    }

    #[tokio::test]
    async fn an_expired_token_is_refreshed_instead_of_reused() {
        // Already past `expires_at`: the skew rule must refuse it, so every
        // lookup re-authenticates.
        let (mock, base) = keystone_and_nova("2020-01-01T00:00:00.000000Z".to_owned());
        let base = base.get().expect("base").clone();
        let cfg = os_config(&urls(&base));
        let client = OpenStackClient::new(cfg).expect("client");

        client.resolve(&req(UUID)).await.expect("first");
        client.resolve(&req(UUID)).await.expect("second");

        assert_eq!(
            mock.count("/v3/auth/tokens"),
            2,
            "expired token never reused"
        );
    }

    #[tokio::test]
    async fn nova_401_refreshes_the_token_once_and_succeeds() {
        let base_cell = Arc::new(OnceLock::<String>::new());
        let base_for_handler = Arc::clone(&base_cell);
        let nova_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits_for_handler = Arc::clone(&nova_hits);
        let mock = MockHttp::start(move |request| {
            let base = base_for_handler.get().cloned().unwrap_or_default();
            match request.path.as_str() {
                "/v3/auth/tokens" => Response::token(
                    "subject-token",
                    &token_body("2099-01-01T00:00:00.000000Z", &base),
                ),
                path if path.starts_with("/v2.1/servers/") => {
                    let n = hits_for_handler.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if n == 0 {
                        Response::empty(401)
                    } else {
                        Response::json(
                            200,
                            &server_json(
                                r#"{"private":[{"addr":"10.0.0.7","version":4,"OS-EXT-IPS:type":"fixed"}]}"#,
                            ),
                        )
                    }
                }
                _ => Response::json(404, "{}"),
            }
        });
        base_cell.set(mock.url("")).expect("base url set");
        let base = mock.url("");

        let cfg = os_config(&urls(&base));
        let client = OpenStackClient::new(cfg).expect("client");

        let grant = client.resolve(&req(UUID)).await.expect("recovers");
        assert_eq!(grant.target.host, "10.0.0.7");
        assert_eq!(
            mock.count("/v3/auth/tokens"),
            2,
            "one refresh, no retry storm"
        );
    }

    #[tokio::test]
    async fn upstream_statuses_map_to_the_documented_control_errors() {
        let cases: Vec<(u16, ControlError)> = vec![
            (404, ControlError::NotFound),
            (403, ControlError::Forbidden),
            (429, ControlError::RateLimited),
            (500, ControlError::ServerError),
            (503, ControlError::ServerError),
        ];
        for (status, expected) in cases {
            let base_cell = Arc::new(OnceLock::<String>::new());
            let base_for_handler = Arc::clone(&base_cell);
            let want_status = status;
            let mock = MockHttp::start(move |request| match request.path.as_str() {
                "/v3/auth/tokens" => {
                    let base = base_for_handler.get().cloned().unwrap_or_default();
                    Response::token(
                        "subject-token",
                        &token_body("2099-01-01T00:00:00.000000Z", &base),
                    )
                }
                _ => Response::empty(want_status),
            });
            base_cell.set(mock.url("")).expect("base url set");
            let base = mock.url("");
            let cfg = os_config(&urls(&base));
            let client = OpenStackClient::new(cfg).expect("client");
            let got = client.resolve(&req(UUID)).await.expect_err("must fail");
            assert_eq!(got, expected, "status {status}");
        }
    }

    #[tokio::test]
    async fn keystone_refusal_is_forbidden() {
        let mock = MockHttp::start(|request| match request.path.as_str() {
            "/v3/auth/tokens" => Response::empty(401),
            _ => Response::json(404, "{}"),
        });
        let base = mock.url("");
        let cfg = os_config(&urls(&base));
        let client = OpenStackClient::new(cfg).expect("client");
        let err = client.resolve(&req(UUID)).await.expect_err("refused");
        assert_eq!(err, ControlError::Forbidden);
        assert_eq!(
            mock.count("/v2.1/servers/"),
            0,
            "no Nova call without a token"
        );
    }

    #[tokio::test]
    async fn an_instance_without_addresses_is_not_found() {
        let base_cell = Arc::new(OnceLock::<String>::new());
        let base_for_handler = Arc::clone(&base_cell);
        let mock = MockHttp::start(move |request| match request.path.as_str() {
            "/v3/auth/tokens" => {
                let base = base_for_handler.get().cloned().unwrap_or_default();
                Response::token(
                    "subject-token",
                    &token_body("2099-01-01T00:00:00.000000Z", &base),
                )
            }
            path if path.starts_with("/v2.1/servers/") => Response::json(200, &server_json("{}")),
            _ => Response::json(404, "{}"),
        });
        base_cell.set(mock.url("")).expect("base url set");
        let base = mock.url("");
        let cfg = os_config(&urls(&base));
        let client = OpenStackClient::new(cfg).expect("client");
        let err = client.resolve(&req(UUID)).await.expect_err("no address");
        assert_eq!(err, ControlError::NotFound, "identical to unknown instance");
        let _ = SelectionError::NoAddress;
    }

    #[tokio::test]
    async fn an_ambiguous_instance_is_not_found_unless_first_is_allowed() {
        let addresses =
            r#"{"a":[{"addr":"10.0.0.7","version":4}],"b":[{"addr":"10.0.0.8","version":4}]}"#;
        let base_cell = Arc::new(OnceLock::<String>::new());
        let base_for_handler = Arc::clone(&base_cell);
        let mock = MockHttp::start(move |request| match request.path.as_str() {
            "/v3/auth/tokens" => {
                let base = base_for_handler.get().cloned().unwrap_or_default();
                Response::token(
                    "subject-token",
                    &token_body("2099-01-01T00:00:00.000000Z", &base),
                )
            }
            path if path.starts_with("/v2.1/servers/") => {
                Response::json(200, &server_json(addresses))
            }
            _ => Response::json(404, "{}"),
        });
        base_cell.set(mock.url("")).expect("base url set");
        let base = mock.url("");

        let cfg = os_config(&urls(&base));
        let client = OpenStackClient::new(cfg.clone()).expect("client");
        let err = client.resolve(&req(UUID)).await.expect_err("ambiguous");
        assert_eq!(err, ControlError::NotFound);

        let cfg = OpenStackConfig {
            on_ambiguous: crate::config::OnAmbiguous::First,
            ..cfg
        };
        let client = OpenStackClient::new(cfg).expect("client");
        let grant = client.resolve(&req(UUID)).await.expect("first wins");
        assert_eq!(
            grant.target.host, "10.0.0.7",
            "stable order: network a first"
        );
    }

    #[tokio::test]
    async fn a_non_uuid_principal_never_reaches_the_network() {
        let mock = MockHttp::start(|_| Response::empty(500));
        let base = mock.url("");
        let cfg = os_config(&urls(&base));
        let client = OpenStackClient::new(cfg).expect("client");

        for principal in ["alex_host1", "not-a-uuid-at-all", "../../etc/passwd"] {
            let err = client.resolve(&req(principal)).await.expect_err("refused");
            assert_eq!(err, ControlError::NotFound, "{principal}");
        }
        assert!(
            mock.requests().is_empty(),
            "no request at all: the username must never become part of a URL"
        );
    }

    #[tokio::test]
    async fn an_unreachable_cloud_is_a_transport_error() {
        // Bind and immediately drop a listener to get a port nothing listens on.
        let dead_port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr").port()
        };
        let base = format!("http://127.0.0.1:{dead_port}");
        let cfg = os_config(&format!("{}\ntimeout = \"1s\"", urls(&base)));
        let client = OpenStackClient::new(cfg).expect("client");
        let err = client.resolve(&req(UUID)).await.expect_err("unreachable");
        assert_eq!(err, ControlError::Transport);
    }

    #[tokio::test]
    async fn missing_subject_token_is_a_decode_failure() {
        let mock = MockHttp::start(|request| match request.path.as_str() {
            "/v3/auth/tokens" => Response::json(201, r#"{"token":{}}"#),
            _ => Response::json(404, "{}"),
        });
        let base = mock.url("");
        let cfg = os_config(&urls(&base));
        let client = OpenStackClient::new(cfg).expect("client");
        let err = client.resolve(&req(UUID)).await.expect_err("no token");
        assert_eq!(err, ControlError::Decode);
    }

    #[tokio::test]
    async fn a_static_token_skips_keystone_entirely() {
        let mock = MockHttp::start(|_| {
            Response::json(
                200,
                &server_json(
                    r#"{"private":[{"addr":"10.0.0.7","version":4,"OS-EXT-IPS:type":"fixed"}]}"#,
                ),
            )
        });
        let base = mock.url("");
        let cfg = os_config(&format!(
            "{}\nauth_method = \"token\"\ntoken = \"static-token\"",
            urls(&base)
        ));
        let client = OpenStackClient::new(cfg).expect("client");
        let grant = client.resolve(&req(UUID)).await.expect("resolves");
        assert_eq!(grant.target.host, "10.0.0.7");
        assert_eq!(mock.count("/v3/auth/tokens"), 0, "no Keystone round trip");
        let nova = &mock.requests()[0];
        assert_eq!(nova.header("X-Auth-Token"), Some("static-token"));
    }

    #[tokio::test]
    async fn the_catalog_is_used_when_nova_endpoint_is_absent() {
        let base_cell = Arc::new(OnceLock::<String>::new());
        let base_for_handler = Arc::clone(&base_cell);
        let mock = MockHttp::start(move |request| match request.path.as_str() {
            "/v3/auth/tokens" => {
                let base = base_for_handler.get().cloned().unwrap_or_default();
                Response::token(
                    "subject-token",
                    &token_body("2099-01-01T00:00:00.000000Z", &base),
                )
            }
            path if path.starts_with("/v2.1/servers/") => Response::json(
                200,
                &server_json(
                    r#"{"private":[{"addr":"10.0.0.7","version":4,"OS-EXT-IPS:type":"fixed"}]}"#,
                ),
            ),
            _ => Response::json(404, "{}"),
        });
        base_cell.set(mock.url("")).expect("base url set");
        let base = mock.url("");

        // No nova_endpoint: the URL must come out of the token's catalog.
        let cfg = os_config(&format!(
            "auth_url = \"{base}/v3\"\nnova_endpoint = \"\"\nregion = \"RegionOne\"\ninterface = \"public\""
        ));
        let client = OpenStackClient::new(cfg).expect("client");
        let grant = client.resolve(&req(UUID)).await.expect("resolves");
        assert_eq!(grant.target.host, "10.0.0.7");
        assert_eq!(mock.count(&format!("/v2.1/servers/{UUID}")), 1);
    }

    // --- pure helpers -------------------------------------------------

    #[test]
    fn catalog_endpoint_selection_honours_interface_and_region() {
        let cfg = OpenStackConfig {
            nova_endpoint: String::new(),
            region: "RegionOne".into(),
            interface: EndpointInterface::Internal,
            ..os_config("auth_url = \"https://keystone.invalid/v3\"")
        };
        let catalog: Vec<CatalogService> = serde_json::from_str(
            r#"[{"type":"compute","endpoints":[
                {"interface":"public","region":"RegionOne","url":"https://pub.invalid/v2.1"},
                {"interface":"internal","region":"RegionOne","url":"https://int.invalid/v2.1"}
            ]}]"#,
        )
        .expect("catalog");

        let base = nova_base_from_catalog(&cfg, &catalog).expect("endpoint");
        assert_eq!(base, "https://int.invalid/v2.1");

        // Wrong region -> no endpoint.
        let cfg = OpenStackConfig {
            region: "Nowhere".into(),
            ..cfg
        };
        assert_eq!(
            nova_base_from_catalog(&cfg, &catalog).expect_err("no match"),
            ControlError::ServerError
        );
    }

    #[test]
    fn catalog_without_compute_service_is_a_server_error() {
        let cfg = OpenStackConfig {
            nova_endpoint: String::new(),
            ..os_config("auth_url = \"https://keystone.invalid/v3\"")
        };
        let catalog: Vec<CatalogService> =
            serde_json::from_str(r#"[{"type":"identity","endpoints":[]}]"#).expect("catalog");
        assert_eq!(
            nova_base_from_catalog(&cfg, &catalog).expect_err("no compute"),
            ControlError::ServerError
        );
    }

    #[test]
    fn explicit_nova_endpoint_wins_over_the_catalog() {
        let cfg = os_config(
            "auth_url = \"https://keystone.invalid/v3\"\nnova_endpoint = \"https://explicit.invalid/v2.1\"",
        );
        let catalog: Vec<CatalogService> = serde_json::from_str(r#"[]"#).expect("catalog");
        assert_eq!(
            nova_base_from_catalog(&cfg, &catalog).expect("override"),
            "https://explicit.invalid/v2.1"
        );
    }

    #[test]
    fn rfc3339_timestamps_parse_to_the_expected_instant() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(UNIX_EPOCH));
        assert_eq!(
            parse_rfc3339_utc("1970-01-01T00:00:01Z"),
            Some(UNIX_EPOCH + Duration::from_secs(1))
        );
        assert_eq!(
            parse_rfc3339_utc("1970-01-01T00:01:00+00:00"),
            Some(UNIX_EPOCH + Duration::from_secs(60))
        );
        assert_eq!(
            parse_rfc3339_utc("1970-01-01T01:00:00+01:00"),
            Some(UNIX_EPOCH),
            "offsets are honoured"
        );
        // Fractional seconds are accepted and truncated.
        assert_eq!(
            parse_rfc3339_utc("1970-01-01T00:00:00.500Z"),
            Some(UNIX_EPOCH)
        );
        // Anything malformed yields None rather than a wrong instant.
        for bad in [
            "",
            "not a date",
            "2026-13-01T00:00:00Z",
            "2026-10-14T25:00:00Z",
            "2026-10-14T00:00:00",
            "2026-10-14T00:00:00+99:00",
            "26-10-14T00:00:00Z",
        ] {
            assert_eq!(parse_rfc3339_utc(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_broken_ca_bundle_fails_the_boot_not_the_first_request() {
        let cfg = OpenStackConfig {
            ca_bundle: std::path::PathBuf::from("/nonexistent/openstack-ca.pem"),
            ..os_config(&urls("http://127.0.0.1:1"))
        };
        let err = OpenStackClient::new(cfg).err().expect("must fail at build");
        assert!(
            matches!(err, OpenStackInitError::ReadCaBundle { .. }),
            "{err}"
        );
    }

    #[test]
    fn fixture_helpers_share_a_header_lookup_that_is_case_insensitive() {
        // Guards the mock itself: assertions depend on this.
        let request = Request {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("X-Auth-Token".into(), "abc".into())],
            body: String::new(),
        };
        assert_eq!(request.header("x-auth-token"), Some("abc"));
        assert_eq!(request.header("absent"), None);
        let _: HashMap<(), ()> = HashMap::new();
    }
}
