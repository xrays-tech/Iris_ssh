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

use tokio::sync::Mutex as AsyncMutex;

use serde::Deserialize;

use crate::config::{EndpointInterface, OpenStackAuthMethod, OpenStackConfig, RouteKind};
use crate::resolve::ControlError;
use crate::types::{
    is_instance_name, is_instance_uuid, Policy, ResolveRequest, ResolveResponse, Target,
};

use nova::{
    decode_server, decode_server_list, exact_name_match, map_backend_user, select_address,
    summarize_body, AddressSelection, NovaServer, UserMapping, UserSource,
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
    /// Serialises token *refreshes* (not reads): without it, the first N
    /// concurrent UUID lookups of a cold cache would each POST
    /// `/v3/auth/tokens` — a Keystone stampede at exactly the moment the
    /// gateway is most loaded.
    token_lock: AsyncMutex<()>,
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
            token_lock: AsyncMutex::new(()),
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

    /// Drop the cached token **only if it is still the one Nova just refused**.
    ///
    /// Two sessions can notice a 401 at the same time; the second one to
    /// arrive must not throw away the fresh token the first one already paid
    /// for.
    fn invalidate_token_if(&self, value: &str) {
        let mut guard = self.lock();
        if guard.as_ref().is_some_and(|cached| cached.value == value) {
            *guard = None;
        }
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
                // Single-flight the refresh: exactly one task talks to
                // Keystone, everybody else waits and then reads the cache.
                let _refresh = self.token_lock.lock().await;
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

    /// The `POST {auth_url}/auth/tokens` body — application credentials only.
    ///
    /// `auth_method = "token"` never reaches here: [`Self::acquire`] returns the
    /// static token without contacting Keystone at all (and config validation
    /// already required an explicit `nova_endpoint` for it, because there is no
    /// catalog to consult). The dead `token` arm was removed rather than left
    /// as a trap for whoever next edits this.
    fn auth_body(&self) -> serde_json::Value {
        debug_assert_eq!(
            self.cfg.auth_method,
            OpenStackAuthMethod::ApplicationCredential
        );
        let identity = serde_json::json!({
            "methods": ["application_credential"],
            "application_credential": {
                "id": self.cfg.application_credential_id,
                "secret": self.cfg.application_credential_secret,
            }
        });
        // No `scope` is sent: an application credential is already scoped to
        // the project it was created in — that scope *is* the blast radius,
        // fixed at credential creation, so a request-time scope adds nothing.
        // Keystone also *rejects* an explicit scope on this method with a 401
        // ("Application credentials cannot request a scope" — observed on the
        // real Keystone v3.14; the in-repo mock never enforced the rule).
        serde_json::json!({ "auth": { "identity": identity } })
    }

    // --- Nova --------------------------------------------------------------

    /// `GET {nova}/servers/{uuid}` — the UUID route (show-by-id).
    ///
    /// The path segment is never user-controlled here: the UUID route feeds it
    /// a principal already accepted by [`is_instance_uuid`] in `resolve`, and
    /// the name-route refinement feeds it an id Nova itself returned in the
    /// list body (appendix A.3's defence in depth). It is the *only* thing
    /// appended to the base URL.
    async fn get_server(&self, token: CachedToken, uuid: &str) -> Result<NovaServer, ControlError> {
        let resp = self
            .nova_get(
                token,
                &format!("/servers/{uuid}"),
                None,
                RouteKind::Uuid,
                uuid,
            )
            .await?;
        let raw_len = resp.content_length().unwrap_or(0) as usize;
        let value: serde_json::Value = match resp.json().await {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!(
                    target: "openstack",
                    reason = "decode",
                    route_by = "uuid",
                    %uuid,
                    "Nova server response was not JSON"
                );
                return Err(ControlError::Decode);
            }
        };
        match decode_server(&value) {
            // Both wire shapes are accepted (see [`ServerResponse`]): the flat
            // v2.1 document and the classic `{"server": {…}}` envelope.
            Ok(outcome) if outcome.addresses_present_but_unusable => {
                // Appendix B.3/B.5: `addresses` was there but nothing usable
                // could be read from its shape. Refusing like an unknown
                // instance (NotFound) keeps the client-facing failure
                // homogeneous, while the log names the real cause instead of
                // the misleading `no_network` — with a structural summary,
                // never the body (red line B.7.5).
                tracing::warn!(
                    target: "openstack",
                    reason = "unparseable",
                    route_by = "uuid",
                    %uuid,
                    summary = %summarize_body(&value, raw_len),
                    notes = ?outcome.notes,
                    "Nova returned an addresses structure this gateway could not read"
                );
                Err(ControlError::NotFound)
            }
            Ok(outcome) => Ok(outcome.view),
            Err(err) => {
                tracing::warn!(
                    target: "openstack",
                    reason = "decode",
                    route_by = "uuid",
                    %uuid,
                    error = %err,
                    summary = %summarize_body(&value, raw_len),
                    "Nova server response could not be decoded"
                );
                Err(ControlError::Decode)
            }
        }
    }

    /// `GET {nova}/servers?name={name}` — the name route (list + local filter).
    ///
    /// The name is handed to reqwest as a **query value**, never concatenated
    /// into the path, so it cannot become a path segment, a second parameter
    /// or a host (appendix A.3). Nova's `name` filter is a substring / regular
    /// expression search, so the local exact-match filter is what actually
    /// decides which machine this is — and refuses when the answer is not
    /// exactly one instance.
    async fn find_server_by_name(
        &self,
        token: CachedToken,
        name: &str,
    ) -> Result<NovaServer, ControlError> {
        let resp = self
            .nova_get(
                token,
                "/servers",
                Some(("name", name)),
                RouteKind::Name,
                name,
            )
            .await?;
        let raw_len = resp.content_length().unwrap_or(0) as usize;
        let value: serde_json::Value = match resp.json().await {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!(
                    target: "openstack",
                    reason = "decode",
                    route_by = "name",
                    principal = %name,
                    "Nova server-list response was not JSON"
                );
                return Err(ControlError::Decode);
            }
        };
        let servers = match decode_server_list(&value) {
            Ok(servers) => servers,
            Err(err) => {
                tracing::warn!(
                    target: "openstack",
                    reason = "decode",
                    route_by = "name",
                    principal = %name,
                    error = %err,
                    summary = %summarize_body(&value, raw_len),
                    "Nova server-list response could not be decoded"
                );
                return Err(ControlError::Decode);
            }
        };
        match exact_name_match(servers, name) {
            Ok(server) => {
                // Real clouds (observed against T_3741's Nova) answer the
                // `?name=` list with a *slim* entry — `id`/`links`/`name`,
                // no addresses at all. The list is a directory; the
                // authoritative document is show-by-id, so refine once when
                // the directory entry carries none. The id comes from Nova's
                // own answer, and `get_server` appends nothing but it to the
                // base URL (appendix A.3's defence in depth). The guard is a
                // plain emptiness check, *not* `is_instance_uuid`: a cloud is
                // free to hand back an id this gateway's UUID shape rejects,
                // and a valid directory entry must not go undialled over a
                // formality. Failure stays loud and homogeneous — a 404 or an
                // undecodable body is `NotFound`/`Decode` either way.
                if server.addresses.is_empty() {
                    if let Some(id) = server.id.as_deref().filter(|id| !id.is_empty()) {
                        tracing::debug!(
                            target: "openstack",
                            route_by = "name",
                            principal = %name,
                            %id,
                            "list entry carries no addresses; refining with show-by-id"
                        );
                        let token = self.acquire().await?;
                        return self.get_server(token, id).await;
                    }
                }
                Ok(server)
            }
            Err(err) => {
                // Zero matches and "several machines share this name" are both
                // `not_found` from the outside; only the log distinguishes
                // them, so a name guesser learns nothing (appendix A.3).
                tracing::warn!(
                    target: "openstack",
                    reason = err.reason(),
                    route_by = "name",
                    principal = %name,
                    "name lookup did not yield exactly one instance"
                );
                Err(ControlError::NotFound)
            }
        }
    }

    /// One Nova `GET`, with the shared "refresh the token once on 401" and
    /// "retry once on a connect failure" semantics (plan-openstack §3.2).
    ///
    /// `path` is always built by this module from a validated UUID or the
    /// literal `/servers`; `query` is handed to reqwest, which percent-encodes
    /// it. A user-controlled string therefore never becomes part of a path.
    async fn nova_get(
        &self,
        mut token: CachedToken,
        path: &str,
        query: Option<(&str, &str)>,
        route_by: RouteKind,
        principal: &str,
    ) -> Result<reqwest::Response, ControlError> {
        let mut refreshed = false;
        loop {
            let url = format!("{}{}", token.nova_base, path);
            let microversion = self.cfg.microversion.as_str();
            let resp = self
                .send(|| {
                    let request = self
                        .http
                        .get(&url)
                        .header("X-Auth-Token", token.value.as_str())
                        .header("OpenStack-API-Version", format!("compute {microversion}"))
                        .header("X-OpenStack-Nova-API-Version", microversion);
                    match query {
                        Some((key, value)) => request.query(&[(key, value)]),
                        None => request,
                    }
                })
                .await?;

            let status = resp.status().as_u16();
            if status == 401 && !refreshed {
                // The cached token died under us: drop it, take a new one, and
                // try exactly once more (plan-openstack §3.2).
                tracing::debug!(
                    target: "openstack",
                    reason = "token_expired",
                    route_by = route_by.as_str(),
                    principal,
                    "Nova rejected the cached token; refreshing"
                );
                self.invalidate_token_if(&token.value);
                token = self.acquire().await?;
                refreshed = true;
                continue;
            }

            return match status {
                200 => Ok(resp),
                404 => {
                    tracing::warn!(
                        target: "openstack",
                        reason = "not_found",
                        route_by = route_by.as_str(),
                        principal,
                        "no such instance (or not visible to this credential)"
                    );
                    Err(ControlError::NotFound)
                }
                401 | 403 => {
                    tracing::warn!(
                        target: "openstack",
                        reason = "forbidden",
                        route_by = route_by.as_str(),
                        principal,
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
                        route_by = route_by.as_str(),
                        principal,
                        status,
                        "Nova is unhealthy"
                    );
                    Err(ControlError::ServerError)
                }
                status => {
                    tracing::warn!(
                        target: "openstack",
                        reason = "unexpected_status",
                        route_by = route_by.as_str(),
                        principal,
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
        let principal = req.principal.as_str();

        // Defence in depth (plan-openstack §3.5 red line 3 / appendix A.3):
        // this string is the *only* user-controlled input this client sends to
        // Nova — as a path segment (a canonical UUID) or as the value of the
        // `name` query parameter — so it has to be a shape this route accepts.
        // Rejecting here means even a wiring mistake upstream cannot turn the
        // gateway into an SSRF proxy.
        //
        // UUID shape always wins and is never treated as a name: an instance
        // whose *name* looks like an id must not create ambiguity.
        let is_uuid = is_instance_uuid(principal);
        let route = if is_uuid && self.cfg.route_by.contains(&RouteKind::Uuid) {
            RouteKind::Uuid
        } else if !is_uuid
            && self.cfg.route_by.contains(&RouteKind::Name)
            && is_instance_name(principal)
        {
            RouteKind::Name
        } else {
            tracing::warn!(
                target: "openstack",
                principal,
                client_ip = %req.client_ip,
                reason = "not_routable",
                route_by = ?self.cfg.route_by,
                "refusing to query Nova for a principal this route does not accept"
            );
            return Err(ControlError::NotFound);
        };
        tracing::debug!(
            target: "openstack",
            principal,
            route_by = route.as_str(),
            client_ip = %req.client_ip,
            key_fp = %req.key_fp,
            "resolving instance address"
        );

        let server = match route {
            RouteKind::Uuid => {
                let token = self.acquire().await?;
                self.get_server(token, principal).await?
            }
            RouteKind::Name => {
                let token = self.acquire().await?;
                self.find_server_by_name(token, principal).await?
            }
        };
        self.build_response(server, principal, route)
    }

    /// Select the address and the backend user from an already-fetched server,
    /// and assemble the grant.
    ///
    /// Shared by the UUID and the name route (appendix A.2): once the instance
    /// document is in hand, nothing about the two routes differs, so the
    /// address-selection, user-mapping and policy rules cannot drift apart.
    fn build_response(
        &self,
        server: NovaServer,
        principal: &str,
        route: RouteKind,
    ) -> std::result::Result<ResolveResponse, ControlError> {
        let selection = AddressSelection {
            network: &self.cfg.network,
            family: self.cfg.address_family,
            prefer: self.cfg.prefer,
            on_ambiguous: self.cfg.on_ambiguous,
        };
        let access_ips = server.access_ips();
        let addr = select_address(&server.addresses, &access_ips, &selection).map_err(|err| {
            // Spell out *why*: `no_network` alone reads as "you typo'd the
            // network name", and it was hours of false leads when the real
            // problem was that `addresses` came back empty on the wire. The
            // configured name next to the names Nova actually advertised makes
            // the two cases (`networks: []` vs `networks: ["other"]`)
            // distinguishable at a glance.
            let networks: Vec<&str> = server.addresses.keys().map(String::as_str).collect();
            tracing::warn!(
                target: "openstack",
                principal,
                route_by = route.as_str(),
                reason = err.reason(),
                configured_network = %self.cfg.network,
                networks = ?networks,
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
                principal,
                route_by = route.as_str(),
                reason = "user_map",
                value = %rejected,
                "instance metadata carries an unusable backend login user; \
                 falling through to the configured mapping"
            );
        }
        tracing::debug!(
            target: "openstack",
            principal,
            route_by = route.as_str(),
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

    #[derive(Debug, Clone)]
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
        /// A 200 whose body is not JSON (an HTML error page, a proxy
        /// interstitial). Appendix B: must surface as a decode failure.
        fn non_json(status: u16, body: &str) -> Self {
            Response {
                status,
                headers: vec![("Content-Type".into(), "text/html".into())],
                body: body.to_owned(),
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

    /// Decode a query value the way form-encoding does: `%XX` escapes, plus a
    /// literal `+` for a space (reqwest's `.query()` uses
    /// `application/x-www-form-urlencoded`). Only used by tests to read back
    /// what the gateway sent.
    fn percent_decode(raw: &str) -> String {
        let bytes = raw.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'+' {
                out.push(b' ');
                i += 1;
                continue;
            }
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or_default();
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Parse the `name` out of a recorded `/servers?name=…` request target.
    fn name_query_of(path: &str) -> Option<String> {
        let (_, query) = path.split_once('?')?;
        let mut name = None;
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("name=") {
                name = Some(percent_decode(value));
            }
        }
        name
    }

    /// A mock that issues tokens and serves the **name** route:
    /// `GET /v2.1/servers?name=…` performs a Nova-style *substring* search over
    /// `instances` (a JSON array of bare server documents, no envelope), so
    /// the local exact-match filter is what these tests actually exercise.
    fn keystone_and_nova_list(
        expires_at: String,
        instances: &'static str,
    ) -> (MockHttp, Arc<OnceLock<String>>) {
        let base = Arc::new(OnceLock::<String>::new());
        let base_for_handler = Arc::clone(&base);
        let server = MockHttp::start(move |request| {
            let base = base_for_handler.get().cloned().unwrap_or_default();
            let method = request.method.as_str();
            let path = request.path.as_str();
            if method == "POST" && path == "/v3/auth/tokens" {
                return Response::token("subject-token", &token_body(&expires_at, &base));
            }
            if method == "GET" && path.starts_with("/v2.1/servers?") {
                let needle = name_query_of(path).unwrap_or_default();
                let all: Vec<serde_json::Value> =
                    serde_json::from_str(instances).expect("instance fixtures");
                let matched: Vec<&serde_json::Value> = all
                    .iter()
                    .filter(|server| {
                        server["name"]
                            .as_str()
                            .is_some_and(|name| name.contains(&needle))
                    })
                    .collect();
                return Response::json(200, &serde_json::json!({ "servers": matched }).to_string());
            }
            if method == "GET" && path.starts_with("/v2.1/servers/") {
                return Response::json(200, "{}");
            }
            Response::json(404, "{}")
        });
        base.set(server.url("")).expect("base url set");
        (server, base)
    }

    /// Two instances: the one the tests resolve by name, and a longer name that
    /// Nova's substring filter would also return for a prefix query.
    const NAME_INSTANCES: &str = r#"[
        {"id":"i-1","name":"inst-1","addresses":{"private":[{"addr":"10.0.0.7","version":4,"OS-EXT-IPS:type":"fixed"}]},"metadata":{},"image":{"id":"img-1"}},
        {"id":"i-2","name":"inst-1-shadow","addresses":{"private":[{"addr":"10.0.0.9","version":4,"OS-EXT-IPS:type":"fixed"}]},"metadata":{},"image":{"id":"img-1"}}
    ]"#;

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
            !keystone.body.contains("\"scope\""),
            "no scope for application credentials (Keystone 401s it): {}",
            keystone.body
        );

        let nova = &requests[1];
        assert_eq!(nova.path, format!("/v2.1/servers/{UUID}"));
        assert!(!nova.header("X-Auth-Token").unwrap().is_empty());
        assert_eq!(nova.header("OpenStack-API-Version"), Some("compute 2.1"));
        assert_eq!(nova.header("X-OpenStack-Nova-API-Version"), Some("2.1"));
    }

    /// Regression (caught on a real cloud): a deployment that answers the
    /// classic v2 wire format wraps the resource in `{"server": {…}}`.
    /// Decoding that envelope as a bare `NovaServer` succeeds but loses
    /// `addresses`, so the lookup died with `reason="no_network"` even though
    /// the same request via curl returned a perfectly good address. The body
    /// below is the real response, trimmed to the fields this gateway reads;
    /// the full verbatim capture lives in `nova.rs`.
    #[tokio::test]
    async fn classic_v2_envelope_body_resolves_the_real_instance() {
        const REAL_ID: &str = "d702cf44-7c17-4410-8ac0-6bd3727fe081";
        let envelope = format!(
            r#"{{"server":{{"id":"{REAL_ID}","name":"gpu-f3a3f738","status":"ACTIVE",
               "metadata":{{}},"image":{{"id":"dcbd8815-cb87-4a26-a5b4-992e45269c26"}},
               "addresses":{{"NET3746":[{{"version":4,"addr":"172.16.46.25",
               "OS-EXT-IPS:type":"fixed","OS-EXT-IPS-MAC:mac_addr":"fa:16:3e:18:27:7a"}}]}},
               "accessIPv4":"","accessIPv6":""}}}}"#
        );

        let base_cell = Arc::new(OnceLock::<String>::new());
        let base_for_handler = Arc::clone(&base_cell);
        let mock = MockHttp::start(move |request| {
            let base = base_for_handler.get().cloned().unwrap_or_default();
            match request.path.as_str() {
                "/v3/auth/tokens" => Response::token(
                    "subject-token",
                    &token_body("2099-01-01T00:00:00.000000Z", &base),
                ),
                path if path.starts_with("/v2.1/servers/") => Response::json(200, &envelope),
                _ => Response::json(404, "{}"),
            }
        });
        base_cell.set(mock.url("")).expect("base url set");

        let cfg = os_config(&format!(
            "{}\nnetwork = \"NET3746\"\naddress_family = \"ipv4\"\nprefer = \"fixed\"",
            urls(&mock.url(""))
        ));
        let client = OpenStackClient::new(cfg).expect("client");

        let grant = client.resolve(&req(REAL_ID)).await.expect("resolves");

        assert_eq!(
            grant.target.host, "172.16.46.25",
            "the enveloped address must be selected"
        );
        assert_eq!(grant.target.port, 22);
        assert_eq!(grant.target.user, "cloud-user", "default backend user");
        assert!(grant.policy.agent_forwarding);
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

    // --- instance-name routing (appendix A.2 / A.3) -----------------------

    /// A config with the name route opted in (`route_by = ["uuid","name"]`).
    fn os_config_with_names(base: &str) -> OpenStackConfig {
        os_config(&format!(
            "{urls}\nroute_by = [\"uuid\", \"name\"]",
            urls = urls(base)
        ))
    }

    #[tokio::test]
    async fn a_name_resolves_through_the_list_endpoint_when_opted_in() {
        let (mock, base) =
            keystone_and_nova_list("2099-01-01T00:00:00.000000Z".to_owned(), NAME_INSTANCES);
        let base = base.get().expect("base").clone();
        let client = OpenStackClient::new(os_config_with_names(&base)).expect("client");

        let grant = client
            .resolve(&req("inst-1"))
            .await
            .expect("resolves by name");

        // Nova's substring search also returned `inst-1-shadow`; the local
        // exact-match filter is what chose this machine.
        assert_eq!(grant.target.host, "10.0.0.7");
        assert_eq!(grant.target.port, 22);
        assert_eq!(grant.target.user, "cloud-user");

        let lists: Vec<_> = mock
            .requests()
            .into_iter()
            .filter(|r| r.path.starts_with("/v2.1/servers?name="))
            .collect();
        assert_eq!(lists.len(), 1, "one list lookup, got {lists:?}");
        assert_eq!(lists[0].path, "/v2.1/servers?name=inst-1");
        assert!(
            mock.requests()
                .iter()
                .all(|r| !r.path.contains("/servers/i-")),
            "the name route must never fall back to show-by-id"
        );
    }

    #[tokio::test]
    async fn two_instances_with_the_same_name_are_refused_rather_than_guessed() {
        let instances = r#"[
            {"id":"i-1","name":"twin","addresses":{"private":[{"addr":"10.0.0.7","version":4}]}},
            {"id":"i-2","name":"twin","addresses":{"private":[{"addr":"10.0.0.8","version":4}]}}
        ]"#;
        let (mock, base) =
            keystone_and_nova_list("2099-01-01T00:00:00.000000Z".to_owned(), instances);
        let base = base.get().expect("base").clone();
        let client = OpenStackClient::new(os_config_with_names(&base)).expect("client");

        let err = client.resolve(&req("twin")).await.expect_err("ambiguous");
        assert_eq!(err, ControlError::NotFound, "indistinguishable from 404");
        assert_eq!(
            mock.requests()
                .iter()
                .filter(|r| r.path.starts_with("/v2.1/servers?name="))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn a_name_never_reaches_any_network_while_the_route_is_off() {
        let (mock, base) =
            keystone_and_nova_list("2099-01-01T00:00:00.000000Z".to_owned(), NAME_INSTANCES);
        let base = base.get().expect("base").clone();
        // Default `route_by = ["uuid"]`: this is the pre-O6b world.
        let client = OpenStackClient::new(os_config(&urls(&base))).expect("client");

        let err = client
            .resolve(&req("inst-1"))
            .await
            .expect_err("not routed");
        assert_eq!(err, ControlError::NotFound);
        assert!(
            mock.requests().is_empty(),
            "no Keystone and no Nova traffic for a name while the route is off"
        );
    }

    #[tokio::test]
    async fn a_name_is_only_ever_a_percent_encoded_query_value() {
        // Appendix A.3: whatever the principal contains, the request path is
        // `/servers` and the name is a single encoded parameter value.
        let (mock, base) =
            keystone_and_nova_list("2099-01-01T00:00:00.000000Z".to_owned(), NAME_INSTANCES);
        let base = base.get().expect("base").clone();
        let client = OpenStackClient::new(os_config_with_names(&base)).expect("client");

        for name in ["a&b=c", "x/y", "../etc", "has space", "q?w=1", "%2e%2e"] {
            let err = client
                .resolve(&req(name))
                .await
                .expect_err("no such instance");
            assert_eq!(err, ControlError::NotFound, "{name}");
        }

        let lists: Vec<_> = mock
            .requests()
            .into_iter()
            .filter(|r| r.path.starts_with("/v2.1/servers?"))
            .collect();
        assert_eq!(lists.len(), 6, "one lookup per principal: {lists:?}");
        for request in &lists {
            let (path, query) = request.path.split_once('?').expect("has a query");
            assert_eq!(path, "/v2.1/servers", "the name never touches the path");
            let params: Vec<&str> = query.split('&').collect();
            assert_eq!(params.len(), 1, "exactly one parameter: {query:?}");
            let value = params[0].strip_prefix("name=").expect("the name param");
            assert!(
                !value.contains(' ') && !value.contains('&') && !value.contains('/'),
                "reserved characters must be encoded: {value:?}"
            );
            // The gateway round-trips the name faithfully, whatever it escaped.
            let decoded = name_query_of(&request.path).unwrap_or_default();
            assert!(
                ["a&b=c", "x/y", "../etc", "has space", "q?w=1", "%2e%2e"]
                    .contains(&decoded.as_str()),
                "decoded name must survive: {decoded:?}"
            );
        }
    }

    #[tokio::test]
    async fn names_the_bound_rejects_never_become_requests() {
        // `is_instance_name`: empty, over-long, or carrying control characters.
        let (mock, base) =
            keystone_and_nova_list("2099-01-01T00:00:00.000000Z".to_owned(), NAME_INSTANCES);
        let base = base.get().expect("base").clone();
        let client = OpenStackClient::new(os_config_with_names(&base)).expect("client");

        let over_long = "a".repeat(256);
        for name in ["", "bad\nname", "nul\0byte", over_long.as_str()] {
            let err = client.resolve(&req(name)).await.expect_err("refused");
            assert_eq!(err, ControlError::NotFound, "{name:?}");
        }
        assert!(
            mock.requests().is_empty(),
            "the guard fires before any request is built"
        );
    }

    #[tokio::test]
    async fn a_uuid_still_uses_show_by_id_when_both_routes_are_on() {
        // UUID shape always wins: it is never treated as a name.
        let (mock, base) =
            keystone_and_nova_list("2099-01-01T00:00:00.000000Z".to_owned(), NAME_INSTANCES);
        let base = base.get().expect("base").clone();
        let client = OpenStackClient::new(os_config_with_names(&base)).expect("client");

        let err = client
            .resolve(&req(UUID))
            .await
            .expect_err("not in the fixture");
        assert_eq!(err, ControlError::NotFound);
        let requests = mock.requests();
        let paths: Vec<&str> = requests
            .iter()
            .map(|r| r.path.as_str())
            .filter(|p| p.contains("/servers"))
            .collect();
        assert!(
            paths.contains(&format!("/v2.1/servers/{UUID}").as_str()),
            "show-by-id for a UUID, got {paths:?}"
        );
        assert!(
            paths.iter().all(|p| !p.contains("?name=")),
            "a UUID must never be looked up by name: {paths:?}"
        );
    }

    /// Real-cloud catch (T_3741's Nova): the `?name=` list answers with a
    /// *slim* entry — `id`/`links`/`name`, no addresses at all. The list is a
    /// directory, so the gateway must refine the unique match with one
    /// show-by-id instead of dialing nothing.
    #[tokio::test]
    async fn a_slim_list_entry_is_refined_with_show_by_id() {
        let base = Arc::new(OnceLock::<String>::new());
        let base_for_handler = Arc::clone(&base);
        let mock = MockHttp::start(move |request| {
            let base = base_for_handler.get().cloned().unwrap_or_default();
            match (request.method.as_str(), request.path.as_str()) {
                ("POST", "/v3/auth/tokens") => Response::token(
                    "subject-token",
                    &token_body("2099-01-01T00:00:00.000000Z", &base),
                ),
                // The slim directory answer, exactly as the real cloud sends
                // it — including a *non-v4* id (T_3741's e52bce4c…): the
                // refinement must not gate on a UUID variant bit real Nova
                // does not promise.
                ("GET", path) if path.starts_with("/v2.1/servers?") => Response::json(
                    200,
                    r#"{"servers":[{"id":"550e8400-e29b-41d4-a716-446655440024","name":"inst-1","links":[]}]}"#,
                ),
                ("GET", path) if path.starts_with("/v2.1/servers/") => Response::json(
                    200,
                    &server_json(
                        r#"{"private":[{"addr":"10.0.0.7","version":4,"OS-EXT-IPS:type":"fixed"}]}"#,
                    ),
                ),
                _ => Response::json(404, "{}"),
            }
        });
        base.set(mock.url("")).expect("base url set");
        let base = base.get().expect("base").clone();
        let client = OpenStackClient::new(os_config_with_names(&base)).expect("client");

        let grant = client
            .resolve(&req("inst-1"))
            .await
            .expect("resolves via the refinement");

        assert_eq!(grant.target.host, "10.0.0.7");
        assert_eq!(grant.target.user, "cloud-user");
        let paths: Vec<String> = mock.requests().into_iter().map(|r| r.path).collect();
        assert!(
            paths.iter().any(|p| p.starts_with("/v2.1/servers?")),
            "the list lookup happened: {paths:?}"
        );
        assert!(
            paths
                .iter()
                .any(|p| p == "/v2.1/servers/550e8400-e29b-41d4-a716-446655440024"),
            "and was refined with show-by-id: {paths:?}"
        );
    }

    /// The refinement must not demand a UUID-shaped id. Appendix A.3's SSRF
    /// defence lives in `get_server` appending nothing but the id Nova itself
    /// returned to the base URL; gating on a form here would leave a valid
    /// directory entry undialled and resolve to nothing (which, for T_3741's
    /// slim list, is exactly the `no_network` failure this layer exists to
    /// stop).
    #[tokio::test]
    async fn the_refinement_does_not_demand_a_uuid_shaped_id() {
        let base = Arc::new(OnceLock::<String>::new());
        let base_for_handler = Arc::clone(&base);
        let mock = MockHttp::start(move |request| {
            let base = base_for_handler.get().cloned().unwrap_or_default();
            match (request.method.as_str(), request.path.as_str()) {
                ("POST", "/v3/auth/tokens") => Response::token(
                    "subject-token",
                    &token_body("2099-01-01T00:00:00.000000Z", &base),
                ),
                ("GET", path) if path.starts_with("/v2.1/servers?") => Response::json(
                    200,
                    r#"{"servers":[{"id":"inst-1-id","name":"inst-1","links":[]}]}"#,
                ),
                ("GET", path) if path.starts_with("/v2.1/servers/") => Response::json(
                    200,
                    &server_json(
                        r#"{"private":[{"addr":"10.0.0.7","version":4,"OS-EXT-IPS:type":"fixed"}]}"#,
                    ),
                ),
                _ => Response::json(404, "{}"),
            }
        });
        base.set(mock.url("")).expect("base url set");
        let base = base.get().expect("base").clone();
        let client = OpenStackClient::new(os_config_with_names(&base)).expect("client");

        let grant = client
            .resolve(&req("inst-1"))
            .await
            .expect("a non-UUID directory id still refines");

        assert_eq!(grant.target.host, "10.0.0.7");
        assert!(
            mock.requests()
                .iter()
                .any(|r| r.path == "/v2.1/servers/inst-1-id"),
            "the non-UUID id was dialled as-is: {:?}",
            mock.requests()
        );
    }

    /// A 200 body the gateway cannot use must fail loudly at the lookup, and
    /// the client-facing outcome must stay homogeneous (appendix B.4 / red
    /// line B.7.3): unreadable `addresses` is a NotFound, like "no such
    /// instance"; a body that is not even JSON is a Decode failure.
    #[tokio::test]
    async fn an_unusable_200_body_fails_loudly_and_homogeneously() {
        async fn resolve_with_server_body(body: Response) -> ControlError {
            let base = Arc::new(OnceLock::<String>::new());
            let base_for_handler = Arc::clone(&base);
            let server = MockHttp::start(move |request| {
                let base = base_for_handler.get().cloned().unwrap_or_default();
                match (request.method.as_str(), request.path.as_str()) {
                    ("POST", "/v3/auth/tokens") => Response::token(
                        "subject-token",
                        &token_body("2099-01-01T00:00:00.000000Z", &base),
                    ),
                    ("GET", path) if path.starts_with("/v2.1/servers/") => body.clone(),
                    _ => Response::json(404, "{}"),
                }
            });
            base.set(server.url("")).expect("base url set");
            let base = base.get().expect("base").clone();
            let client = OpenStackClient::new(os_config(&urls(&base))).expect("client");
            client.resolve(&req(UUID)).await.expect_err("must fail")
        }

        // A 200 that is not JSON at all (an HTML proxy page, say).
        let err = resolve_with_server_body(Response::non_json(
            200,
            "<html><body>upstream proxy error</body></html>",
        ))
        .await;
        assert_eq!(
            err,
            ControlError::Decode,
            "a body that is not JSON is unreadable"
        );

        // Valid JSON, but `addresses` is a string: the flag path — NotFound
        // for the client (homogeneous), `unparseable` in the log.
        let err =
            resolve_with_server_body(Response::json(200, r#"{"id":"x","addresses":"not-a-map"}"#))
                .await;
        assert_eq!(err, ControlError::NotFound);

        // A JSON scalar is not a server document either.
        let err = resolve_with_server_body(Response::json(200, "42")).await;
        assert_eq!(err, ControlError::Decode);
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

    #[tokio::test]
    async fn concurrent_lookups_share_a_single_token_fetch() {
        // Cold-cache stampede: N UUIDs arriving at once must produce ONE
        // `POST /v3/auth/tokens`, not N. The handler holds the first answer
        // long enough for the other tasks to arrive while the cache is empty.
        let base = Arc::new(OnceLock::<String>::new());
        let base_for_handler = Arc::clone(&base);
        let server = MockHttp::start(move |request| {
            let base = base_for_handler.get().cloned().unwrap_or_default();
            match (request.method.as_str(), request.path.as_str()) {
                ("POST", "/v3/auth/tokens") => {
                    std::thread::sleep(Duration::from_millis(200));
                    Response::token(
                        "subject-token",
                        &token_body("2099-01-01T00:00:00.000000Z", &base),
                    )
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

        let cfg = os_config(&urls(base.get().expect("base")));
        let client = Arc::new(OpenStackClient::new(cfg).expect("client"));

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let client = Arc::clone(&client);
            tasks.push(tokio::spawn(async move {
                client.resolve(&req(UUID)).await.expect("resolves")
            }));
        }
        for task in tasks {
            task.await.expect("join");
        }

        assert_eq!(
            server.count("/v3/auth/tokens"),
            1,
            "the token refresh must be single-flighted"
        );
        assert_eq!(
            server.count(&format!("/v2.1/servers/{UUID}")),
            8,
            "each lookup still makes its own Nova request"
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
