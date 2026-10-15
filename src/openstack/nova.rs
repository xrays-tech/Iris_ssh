//! Pure Nova helpers: response parsing, address selection, backend-user
//! mapping (plan-openstack §3.3 / §3.4).
//!
//! Nothing in this module touches the network or the config file, so every
//! decision that could send a session to the wrong address — or log in as the
//! wrong user — is a plain function with table-driven tests.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Deserializer};

use crate::config::{AddressFamily, BackendUserRule, IpPrefer, OnAmbiguous};

/// A parsed `server.addresses` entry: `{ "net-name": [ {...}, ... ] }`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct NovaAddress {
    #[serde(default)]
    pub addr: Option<String>,
    #[serde(default)]
    pub version: Option<u8>,
    /// `"fixed"` / `"floating"` (`OS-EXT-IPS:type`); absent on some clouds.
    #[serde(rename = "OS-EXT-IPS:type", default)]
    pub addr_type: Option<String>,
}

/// `server.image`: `{"id": "..."}`.
///
/// Real clouds also send `null` (deleted image) and the bare empty string `""`
/// (volume-backed server, or an image that is gone) — see [`image_or_none`].
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct NovaImage {
    #[serde(default)]
    pub id: Option<String>,
}

/// Accept every form `server.image` takes in the wild, and treat all of them
/// but the object as "no image".
///
/// The reference shape is `{"id": "..."}`; `null` and an absent key already
/// mean "no image". But a real deployment (project T_3741) answers with the
/// bare empty string `""`, and that string failed to deserialize into
/// [`NovaImage`] — which, through the envelope/flat dispatch in
/// [`ServerResponse`], used to cost the whole lookup. A field this gateway
/// never acts on must not be able to break address resolution.
fn image_or_none<'de, D>(deserializer: D) -> Result<Option<NovaImage>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|raw| match raw {
        serde_json::Value::Object(_) => NovaImage::deserialize(raw).ok(),
        // `""`, a bare id string, a number, an array … — none of these is an
        // image reference this gateway could use, so none is worth failing on.
        _ => None,
    }))
}

/// The subset of `GET /v2.1/servers/{id}` this gateway uses.
///
/// Every field is optional so a cloud that omits one (metadata, image, the
/// legacy accessIPv4) still decodes — only `addresses` matters, and that has a
/// documented fallback below.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct NovaServer {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub addresses: BTreeMap<String, Vec<NovaAddress>>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "image_or_none")]
    pub image: Option<NovaImage>,
    #[serde(rename = "accessIPv4", default)]
    pub access_ipv4: Option<String>,
    #[serde(rename = "accessIPv6", default)]
    pub access_ipv6: Option<String>,
}

impl NovaServer {
    /// Legacy `accessIPv4` / `accessIPv6` literals, kept only as a fallback
    /// when `addresses` yields nothing at all (plan-openstack §3.3).
    pub fn access_ips(&self) -> Vec<IpAddr> {
        let mut out = Vec::with_capacity(2);
        for raw in [self.access_ipv4.as_deref(), self.access_ipv6.as_deref()] {
            let Some(raw) = raw else { continue };
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            if let Ok(ip) = raw.parse::<IpAddr>() {
                out.push(ip);
            }
        }
        out
    }

    /// Glance image id, when Nova still reports one.
    pub fn image_id(&self) -> Option<&str> {
        self.image.as_ref().and_then(|img| img.id.as_deref())
    }
}

/// The two shapes a `GET /servers/{id}` body may take.
///
/// The v2.1 reference documents the flat form, and that is what upstream
/// DevStack and this repo's mock return. But deployments that still expose the
/// classic v2 wire format — every OpenStack API-compat layer (v2 compat,
/// vendor clouds, older `osapi_compute`) — wrap the resource:
///
/// ```json
/// {"server": {"id": "…", "addresses": {"NET3746": [ … ]}}}
/// ```
///
/// Caught the hard way against a real cloud: decoding the envelope as a
/// [`NovaServer`] succeeds (every field is optional) but yields *empty*
/// `addresses`, so `[openstack] network` matched nothing and the lookup died
/// with the misleading `reason="no_network"` — while the very same request via
/// curl returned the addresses just fine. Accept both shapes so a wire-format
/// difference can never again masquerade as a configuration error.
///
/// The variant is chosen by **shape** (does the document carry a `server`
/// key?), not by `#[serde(untagged)]` trial and error. Untagged falls through
/// to the next variant whenever one fails, and because every field of
/// [`NovaServer`] is optional, a single field of an unexpected type anywhere
/// inside an envelope used to "successfully" decode the whole document as an
/// empty server: the lookup then failed with `no_network` and `networks=[]`
/// instead of naming the field that broke. That is exactly how a second real
/// cloud (project T_3741, `"image": ""`) went dark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerResponse {
    /// `{"server": { … }}` (classic v2 envelope).
    Envelope { server: NovaServer },
    /// `{ … }` (v2.1 flat document).
    Flat(NovaServer),
}

impl<'de> Deserialize<'de> for ServerResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value.get("server") {
            // Envelope: decode the nested document *strictly*, so a type
            // surprise inside it surfaces as a decode failure (loud, logged as
            // `reason="decode"`) rather than silently emptying `addresses`.
            Some(inner) => NovaServer::deserialize(inner)
                .map(|server| ServerResponse::Envelope { server })
                .map_err(serde::de::Error::custom),
            // Flat document: no wrapper key in sight.
            None => NovaServer::deserialize(value)
                .map(ServerResponse::Flat)
                .map_err(serde::de::Error::custom),
        }
    }
}

impl ServerResponse {
    /// The enclosed [`NovaServer`], whichever shape it arrived in.
    pub fn into_server(self) -> NovaServer {
        match self {
            ServerResponse::Envelope { server } => server,
            ServerResponse::Flat(server) => server,
        }
    }
}

/// Why an address could not be selected. Logged as `reason=...` and mapped to
/// a client-facing `ControlError::NotFound` so every refusal is identical from
/// the outside (plan-openstack §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionError {
    /// No address survived parsing / filtering.
    NoAddress,
    /// The configured `[openstack] network` does not exist on this instance.
    NoNetwork,
    /// More than one address survived and `on_ambiguous = "reject"`.
    Ambiguous,
}

impl SelectionError {
    /// Stable reason token used in logs and audit output.
    pub fn reason(self) -> &'static str {
        match self {
            SelectionError::NoAddress => "no_address",
            SelectionError::NoNetwork => "no_network",
            SelectionError::Ambiguous => "ambiguous",
        }
    }
}

/// One address candidate: which network it came from, what it is, and whether
/// it is fixed or floating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub network: String,
    pub addr: IpAddr,
    pub kind: AddrKind,
}

/// `OS-EXT-IPS:type`, defaulted to `Unknown` when the cloud does not say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddrKind {
    Floating,
    Fixed,
    Unknown,
}

/// Selection knobs, borrowed from the `[openstack]` config.
#[derive(Debug, Clone, Copy)]
pub struct AddressSelection<'a> {
    pub network: &'a str,
    pub family: AddressFamily,
    pub prefer: IpPrefer,
    pub on_ambiguous: OnAmbiguous,
}

/// Expand `server.addresses` into candidates, dropping anything that is not a
/// parseable IP literal (a malformed entry must not be dialed).
pub fn candidates(addresses: &BTreeMap<String, Vec<NovaAddress>>) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (network, entries) in addresses {
        for entry in entries {
            let Some(raw) = entry.addr.as_deref() else {
                continue;
            };
            let raw = raw.trim();
            let Ok(addr) = raw.parse::<IpAddr>() else {
                continue;
            };
            // Trust the parsed literal over the advertised `version` field: the
            // literal is what would be dialed.
            out.push(Candidate {
                network: network.clone(),
                addr,
                kind: match entry.addr_type.as_deref() {
                    Some("floating") => AddrKind::Floating,
                    Some("fixed") => AddrKind::Fixed,
                    _ => AddrKind::Unknown,
                },
            });
        }
    }
    out
}

fn matches_family(addr: IpAddr, family: AddressFamily) -> bool {
    match family {
        AddressFamily::Any => true,
        AddressFamily::IPv4 => addr.is_ipv4(),
        AddressFamily::IPv6 => addr.is_ipv6(),
    }
}

fn type_rank(kind: AddrKind, prefer: IpPrefer) -> u8 {
    // `any` still prefers floating: it is the address most likely to be
    // reachable from outside the instance's own network (plan-openstack §3.3).
    let floating_first = matches!(prefer, IpPrefer::Floating | IpPrefer::Any);
    match kind {
        AddrKind::Floating if floating_first => 0,
        AddrKind::Floating => 1,
        AddrKind::Fixed if floating_first => 1,
        AddrKind::Fixed => 0,
        AddrKind::Unknown => 2,
    }
}

/// Apply plan-openstack §3.3:
///
/// 1. expand + dedup candidates, 2. `network` filter, 3. address-family filter,
/// 4. `prefer` ordering (floating before fixed unless told otherwise).
///
/// Then exactly one address is used, none is an error, and several are refused
/// unless `on_ambiguous = "first"` (the first in the stable order wins and the
/// caller warns).
///
/// `access_ips` is consulted **only** when the instance's own `addresses`
/// yielded nothing *and* no `network` filter was configured: the legacy
/// `accessIPv4/6` fields carry no network attribution, so honouring them
/// against an explicit network filter would defeat it.
pub fn select_address(
    addresses: &BTreeMap<String, Vec<NovaAddress>>,
    access_ips: &[IpAddr],
    sel: &AddressSelection<'_>,
) -> Result<IpAddr, SelectionError> {
    let mut cands = candidates(addresses);

    if !sel.network.is_empty() {
        if !cands.iter().any(|c| c.network == sel.network) {
            return Err(SelectionError::NoNetwork);
        }
        cands.retain(|c| c.network == sel.network);
    }
    cands.retain(|c| matches_family(c.addr, sel.family));

    if cands.is_empty() && sel.network.is_empty() {
        for ip in access_ips {
            if matches_family(*ip, sel.family) {
                cands.push(Candidate {
                    network: String::new(),
                    addr: *ip,
                    kind: AddrKind::Unknown,
                });
            }
        }
    }

    if cands.is_empty() {
        return Err(SelectionError::NoAddress);
    }

    // Deterministic base order, so duplicates collapse and `first` is stable.
    cands.sort_by(|a, b| {
        a.network
            .cmp(&b.network)
            .then_with(|| a.addr.cmp(&b.addr))
            .then_with(|| a.kind.cmp(&b.kind))
    });
    cands.dedup_by(|a, b| a.network == b.network && a.addr == b.addr);

    // Stable sort keeps the (network, addr) order for equal preference.
    // `sort_by_key` is stable, so ties keep the (network, addr) order.
    cands.sort_by_key(|candidate| type_rank(candidate.kind, sel.prefer));

    if cands.len() == 1 {
        return Ok(cands[0].addr);
    }
    match sel.on_ambiguous {
        OnAmbiguous::Reject => Err(SelectionError::Ambiguous),
        OnAmbiguous::First => Ok(cands[0].addr),
    }
}

/// Which source produced the backend login user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSource {
    /// Instance metadata (`backend_user_metadata_key`).
    Metadata,
    /// `[[openstack.backend_user_map]]` rule index.
    Rule(usize),
    /// `default_backend_user`.
    Default,
}

impl UserSource {
    pub fn as_str(self) -> &'static str {
        match self {
            UserSource::Metadata => "metadata",
            UserSource::Rule(_) => "rule",
            UserSource::Default => "default",
        }
    }
}

/// The chosen login user, plus any higher-priority value that was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserChoice {
    pub user: String,
    pub source: UserSource,
    /// A metadata value that was present but unusable (empty / whitespace /
    /// control characters). The caller logs it; the chain continues with the
    /// next source instead — an instance's own label must never be able to
    /// break every login to that instance *and* trip the shared breaker.
    pub rejected_metadata: Option<String>,
}

/// Backend-login-user mapping, plan-openstack §3.4 priority:
/// metadata → first matching rule → `default_backend_user`.
pub struct UserMapping<'a> {
    pub metadata_key: &'a str,
    pub rules: &'a [BackendUserRule],
    pub default: &'a str,
}

/// Is `value` safe to hand to the backend as a login name?
///
/// Mirrors the config-time check: non-empty, no whitespace, no control
/// characters. It is re-checked here because metadata is *runtime* data.
pub fn valid_user(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn name_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_prefix('^') {
        Some(prefix) => name.starts_with(prefix),
        None => name == pattern,
    }
}

fn rule_matches(rule: &BackendUserRule, name: &str, metadata: &BTreeMap<String, String>) -> bool {
    let name_ok = rule.match_name.is_empty() || name_matches(&rule.match_name, name);
    let meta_ok = rule
        .match_metadata
        .iter()
        .all(|(key, want)| metadata.get(key).is_some_and(|have| have == want));
    name_ok && meta_ok
}

/// Pick the backend login user for one instance.
pub fn map_backend_user(
    metadata: &BTreeMap<String, String>,
    name: &str,
    mapping: &UserMapping<'_>,
) -> UserChoice {
    // 1. Instance metadata — the zero-config path an operator gets by labelling
    //    the instance when creating it.
    if !mapping.metadata_key.is_empty() {
        if let Some(raw) = metadata.get(mapping.metadata_key) {
            if valid_user(raw) {
                return UserChoice {
                    user: raw.clone(),
                    source: UserSource::Metadata,
                    rejected_metadata: None,
                };
            }
            // Refuse the label but keep the chain going: see UserChoice docs.
            return rule_then_default(metadata, name, mapping, Some(raw.clone()));
        }
    }
    rule_then_default(metadata, name, mapping, None)
}

fn rule_then_default(
    metadata: &BTreeMap<String, String>,
    name: &str,
    mapping: &UserMapping<'_>,
    rejected: Option<String>,
) -> UserChoice {
    for (idx, rule) in mapping.rules.iter().enumerate() {
        if rule_matches(rule, name, metadata) {
            return UserChoice {
                user: rule.user.clone(),
                source: UserSource::Rule(idx),
                rejected_metadata: rejected,
            };
        }
    }
    // `default_backend_user` is non-empty and validated at config time, so the
    // chain always resolves here.
    UserChoice {
        user: mapping.default.to_owned(),
        source: UserSource::Default,
        rejected_metadata: rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackendUserRule;
    use std::collections::BTreeMap;

    fn addr(net: &str, ip: &str, kind: &str) -> (String, Vec<NovaAddress>) {
        (
            net.to_owned(),
            vec![NovaAddress {
                addr: Some(ip.to_owned()),
                version: Some(if ip.contains(':') { 6 } else { 4 }),
                addr_type: Some(kind.to_owned()),
            }],
        )
    }

    fn selection<'a>(
        network: &'a str,
        family: AddressFamily,
        prefer: IpPrefer,
        on_ambiguous: OnAmbiguous,
    ) -> AddressSelection<'a> {
        AddressSelection {
            network,
            family,
            prefer,
            on_ambiguous,
        }
    }

    fn map(entries: Vec<(String, Vec<NovaAddress>)>) -> BTreeMap<String, Vec<NovaAddress>> {
        entries.into_iter().collect()
    }

    #[test]
    fn parses_single_network_single_address() {
        let json = r#"{"addresses":{"private":[{"addr":"10.0.0.7","version":4,"OS-EXT-IPS:type":"fixed"}]}}"#;
        let server: NovaServer = serde_json::from_str(json).expect("decodes");
        assert_eq!(server.addresses.len(), 1);
        let got = select_address(
            &server.addresses,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .expect("one address");
        assert_eq!(got, "10.0.0.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn missing_addresses_field_decodes_as_empty() {
        let server: NovaServer = serde_json::from_str(r#"{"id":"u"}"#).expect("decodes");
        assert!(server.addresses.is_empty());
        assert!(server.metadata.is_empty());
        assert_eq!(server.image_id(), None);
        let err = select_address(
            &server.addresses,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .unwrap_err();
        assert_eq!(err, SelectionError::NoAddress);
        assert_eq!(err.reason(), "no_address");
    }

    #[test]
    fn parses_metadata_and_image() {
        let json =
            r#"{"name":"web-1","metadata":{"iris_ssh_user":"alice"},"image":{"id":"img-1"}}"#;
        let server: NovaServer = serde_json::from_str(json).expect("decodes");
        assert_eq!(server.name.as_deref(), Some("web-1"));
        assert_eq!(server.image_id(), Some("img-1"));
        assert_eq!(
            server.metadata.get("iris_ssh_user").map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn floating_wins_over_fixed_and_v6_is_droppable() {
        let addrs = map(vec![
            addr("private", "10.0.0.7", "fixed"),
            addr("public", "192.0.2.10", "floating"),
            addr("v6", "2001:db8::7", "fixed"),
        ]);

        // Two IPv4 survivors is ambiguity: refused by default...
        let err = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .unwrap_err();
        assert_eq!(err, SelectionError::Ambiguous);

        // ...and ordered by `prefer` once the operator opts into `first`.
        let got = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Floating,
                OnAmbiguous::First,
            ),
        )
        .expect("floating v4 first");
        assert_eq!(got, "192.0.2.10".parse::<IpAddr>().unwrap());

        let got = select_address(
            &addrs,
            &[],
            &selection("", AddressFamily::IPv4, IpPrefer::Fixed, OnAmbiguous::First),
        )
        .expect("fixed v4 first");
        assert_eq!(got, "10.0.0.7".parse::<IpAddr>().unwrap());

        // The family filter alone leaves exactly one candidate, so IPv6 works
        // even with `reject`.
        let got = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::IPv6,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .expect("v6");
        assert_eq!(got, "2001:db8::7".parse::<IpAddr>().unwrap());
    }
    #[test]
    fn network_filter_narrows_and_absent_network_fails_loud() {
        let addrs = map(vec![
            addr("private", "10.0.0.7", "fixed"),
            addr("public", "192.0.2.10", "floating"),
        ]);
        let got = select_address(
            &addrs,
            &[],
            &selection(
                "private",
                AddressFamily::Any,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .expect("private wins");
        assert_eq!(got, "10.0.0.7".parse::<IpAddr>().unwrap());

        let err = select_address(
            &addrs,
            &[],
            &selection(
                "mgmt",
                AddressFamily::Any,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .unwrap_err();
        assert_eq!(err, SelectionError::NoNetwork);
        assert_eq!(err.reason(), "no_network");
    }

    #[test]
    fn multiple_candidates_are_rejected_by_default_and_truncated_on_request() {
        let addrs = map(vec![
            addr("private", "10.0.0.7", "fixed"),
            addr("public", "192.0.2.10", "floating"),
        ]);
        let err = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::Any,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .unwrap_err();
        assert_eq!(err, SelectionError::Ambiguous);
        assert_eq!(err.reason(), "ambiguous");

        // `first` takes the preference-ordered first: floating before fixed.
        let got = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::Any,
                IpPrefer::Floating,
                OnAmbiguous::First,
            ),
        )
        .expect("first mode");
        assert_eq!(got, "192.0.2.10".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn first_mode_is_deterministic_for_equal_preference() {
        let addrs = map(vec![
            addr("b-net", "10.0.0.2", "fixed"),
            addr("a-net", "10.0.0.1", "fixed"),
        ]);
        let one = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::Any,
                IpPrefer::Floating,
                OnAmbiguous::First,
            ),
        )
        .unwrap();
        let two = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::Any,
                IpPrefer::Floating,
                OnAmbiguous::First,
            ),
        )
        .unwrap();
        assert_eq!(one, two, "must not depend on hash/map order");
        assert_eq!(one, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn duplicate_entries_do_not_create_false_ambiguity() {
        let addrs = map(vec![(
            "private".to_owned(),
            vec![
                NovaAddress {
                    addr: Some("10.0.0.7".into()),
                    version: Some(4),
                    addr_type: Some("fixed".into()),
                },
                NovaAddress {
                    addr: Some("10.0.0.7".into()),
                    version: Some(4),
                    addr_type: Some("fixed".into()),
                },
            ],
        )]);
        let got = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::Any,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .expect("same address twice is one candidate");
        assert_eq!(got, "10.0.0.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn unparseable_and_mismatched_entries_are_ignored() {
        let addrs = map(vec![(
            "private".to_owned(),
            vec![
                NovaAddress {
                    addr: Some("not-an-ip".into()),
                    version: Some(4),
                    addr_type: None,
                },
                NovaAddress {
                    addr: None,
                    version: Some(4),
                    addr_type: None,
                },
                NovaAddress {
                    addr: Some(" 10.0.0.7 ".into()),
                    version: Some(4),
                    addr_type: None,
                },
            ],
        )]);
        let got = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .expect("one good address");
        assert_eq!(got, "10.0.0.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn access_ip_fallback_only_when_addresses_are_empty_and_unfiltered() {
        // No addresses at all -> the legacy field rescues the lookup.
        let got = select_address(
            &BTreeMap::new(),
            &[IpAddr::from([192, 0, 2, 55])],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .expect("fallback address");
        assert_eq!(got, "192.0.2.55".parse::<IpAddr>().unwrap());

        // A configured network suppresses the fallback: it carries no
        // attribution, so it cannot be shown to belong to that network.
        let err = select_address(
            &BTreeMap::new(),
            &[IpAddr::from([192, 0, 2, 55])],
            &selection(
                "private",
                AddressFamily::Any,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .unwrap_err();
        assert_eq!(err, SelectionError::NoNetwork);

        // Family filter still applies to the fallback.
        let err = select_address(
            &BTreeMap::new(),
            &[IpAddr::from([192, 0, 2, 55])],
            &selection(
                "",
                AddressFamily::IPv6,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
            ),
        )
        .unwrap_err();
        assert_eq!(err, SelectionError::NoAddress);
    }

    #[test]
    fn access_ips_are_parsed_from_both_legacy_fields() {
        let json = r#"{"accessIPv4":"192.0.2.55","accessIPv6":"2001:db8::9"}"#;
        let server: NovaServer = serde_json::from_str(json).expect("decodes");
        assert_eq!(
            server.access_ips(),
            vec![
                IpAddr::from([192, 0, 2, 55]),
                "2001:db8::9".parse::<IpAddr>().unwrap()
            ]
        );
        // Garbage is dropped rather than dialed.
        let json = r#"{"accessIPv4":"not-an-ip","accessIPv6":""}"#;
        let server: NovaServer = serde_json::from_str(json).expect("decodes");
        assert!(server.access_ips().is_empty());
    }

    /// A **verbatim** `GET /v2.1/servers/{id}` body captured from a real
    /// deployment (`nova_endpoint = 172.16.29.18:8774/v2.1`, instance
    /// `d702cf44-7c17-4410-8ac0-6bd3727fe081`, network `NET3746`).
    ///
    /// Note the shape: the resource is wrapped in `{"server": …}`. That is
    /// what the live cloud returned for the *same* request the gateway sends,
    /// and it is why the gateway refused with `reason="no_network"` while
    /// curl showed a perfectly good address.
    const REAL_ENVELOPE: &str = r#"{
        "server": {
            "id": "d702cf44-7c17-4410-8ac0-6bd3727fe081",
            "name": "gpu-f3a3f738-d26f-402d-a986-ac7b90394ac9",
            "status": "ACTIVE",
            "tenant_id": "a070dab7800e4eff88ad72e11f864471",
            "user_id": "9e8501ed43644dda92541ebe5f195444",
            "metadata": {},
            "hostId": "0238b0cb597c849d040c308f3d94c6636b10e741a04df8a8e32c8d00",
            "image": {
                "id": "dcbd8815-cb87-4a26-a5b4-992e45269c26",
                "links": [
                    {
                        "rel": "bookmark",
                        "href": "http://172.16.29.18:8774/images/dcbd8815-cb87-4a26-a5b4-992e45269c26"
                    }
                ]
            },
            "flavor": {
                "id": "903648e3-bf5d-4800-a8fe-e19dc85c61c3",
                "links": [
                    {
                        "rel": "bookmark",
                        "href": "http://172.16.29.18:8774/flavors/903648e3-bf5d-4800-a8fe-e19dc85c61c3"
                    }
                ]
            },
            "created": "2026-10-12T06:27:57Z",
            "updated": "2026-10-12T06:28:17Z",
            "addresses": {
                "NET3746": [
                    {
                        "version": 4,
                        "addr": "172.16.46.25",
                        "OS-EXT-IPS:type": "fixed",
                        "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:18:27:7a"
                    }
                ]
            },
            "accessIPv4": "",
            "accessIPv6": "",
            "links": [
                {
                    "rel": "self",
                    "href": "http://172.16.29.18:8774/v2.1/servers/d702cf44-7c17-4410-8ac0-6bd3727fe081"
                },
                {
                    "rel": "bookmark",
                    "href": "http://172.16.29.18:8774/servers/d702cf44-7c17-4410-8ac0-6bd3727fe081"
                }
            ],
            "OS-DCF:diskConfig": "MANUAL",
            "progress": 0,
            "OS-EXT-AZ:availability_zone": "GPU_4090_Renting",
            "config_drive": "True",
            "key_name": "rental-e9fbcd0c-5099-4831-a6d0-99eeeb41ca88",
            "OS-SRV-USG:launched_at": "2026-10-12T06:28:17.000000",
            "OS-SRV-USG:terminated_at": null,
            "security_groups": [
                {
                    "name": "default"
                }
            ],
            "OS-EXT-SRV-ATTR:host": "host91",
            "OS-EXT-SRV-ATTR:instance_name": "instance-00000a1a",
            "OS-EXT-SRV-ATTR:hypervisor_hostname": "host91",
            "OS-EXT-STS:task_state": null,
            "OS-EXT-STS:vm_state": "active",
            "OS-EXT-STS:power_state": 1,
            "os-extended-volumes:volumes_attached": []
        }
    }"#;

    /// The real-cloud catch, as a regression test: an enveloped body must
    /// decode *and* yield the address, with the configured network matching.
    #[test]
    fn real_cloud_envelope_body_decodes_and_selects_the_advertised_address() {
        let parsed: ServerResponse = serde_json::from_str(REAL_ENVELOPE).expect("envelope decodes");
        let server = parsed.into_server();

        assert_eq!(
            server.id.as_deref(),
            Some("d702cf44-7c17-4410-8ac0-6bd3727fe081")
        );
        assert_eq!(
            server
                .addresses
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["NET3746"],
            "the wrapped `addresses` map is what used to come back empty"
        );
        assert!(
            server.access_ips().is_empty(),
            "empty legacy fields stay empty"
        );

        let got = select_address(
            &server.addresses,
            &server.access_ips(),
            &AddressSelection {
                network: "NET3746",
                family: AddressFamily::IPv4,
                prefer: IpPrefer::Fixed,
                on_ambiguous: OnAmbiguous::Reject,
            },
        )
        .expect("real instance resolves");
        assert_eq!(got, "172.16.46.25".parse::<IpAddr>().unwrap());
    }

    /// Both wire shapes must decode to the *same* server, so a cloud's format
    /// choice cannot change which address gets dialed.
    #[test]
    fn envelope_and_flat_shapes_decode_to_the_same_server() {
        let envelope: ServerResponse =
            serde_json::from_str(REAL_ENVELOPE).expect("envelope decodes");
        // The flat sibling: the same fields the envelope carries, unwrapped.
        let flat = serde_json::json!({
            "id": "d702cf44-7c17-4410-8ac0-6bd3727fe081",
            "name": "gpu-f3a3f738-d26f-402d-a986-ac7b90394ac9",
            "metadata": {},
            "image": { "id": "dcbd8815-cb87-4a26-a5b4-992e45269c26" },
            "addresses": {
                "NET3746": [
                    {
                        "version": 4,
                        "addr": "172.16.46.25",
                        "OS-EXT-IPS:type": "fixed",
                        "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:18:27:7a"
                    }
                ]
            },
            "accessIPv4": "",
            "accessIPv6": "",
        });
        let flat: ServerResponse = serde_json::from_value(flat).expect("flat decodes");
        assert_eq!(
            envelope.into_server(),
            flat.into_server(),
            "shape must not affect the parsed server"
        );
    }

    /// A **second verbatim** real capture (project T_3741, instance
    /// `e52bce4c-a98e-4f69-906c-ac6648a2e592`): the same classic v2 envelope,
    /// but this cloud reports `"image": ""` — the empty-string form Nova emits
    /// when a server's image is gone (or it was booted from a volume).
    ///
    /// That string is not an object, so it fails the `Envelope` variant, and
    /// serde's untagged fallback then decoded the whole envelope as a *bare*
    /// server — every field optional, so the decode "succeeded" with an empty
    /// `addresses` map. The lookup died with `reason="no_network"` and
    /// `networks=[]` while curl showed a perfectly good 172.16.41.62.
    const REAL_ENVELOPE_T3741: &str = r#"{"server": {"id": "e52bce4c-a98e-4f69-906c-ac6648a2e592", "name": "yunqing_dev", "status": "ACTIVE", "tenant_id": "6bdb5cae363a4c78b14be43b372d821a", "user_id": "3e7ce6a39c884a88a0381e4bd1f782cc", "metadata": {}, "hostId": "953c9b78d9f046367ca96e475f205e4f45a614f535d445d90ca2acd1", "image": "", "flavor": {"id": "6cda4820-0b3d-499a-b5fb-48cae704a3c8", "links": [{"rel": "bookmark", "href": "http://172.16.29.18:8774/flavors/6cda4820-0b3d-499a-b5fb-48cae704a3c8"}]}, "created": "2026-10-08T03:53:46Z", "updated": "2026-10-08T03:53:57Z", "addresses": {"NET3741": [{"version": 4, "addr": "172.16.41.62", "OS-EXT-IPS:type": "fixed", "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:2e:b6:37"}]}, "accessIPv4": "", "accessIPv6": "", "links": [{"rel": "self", "href": "http://172.16.29.18:8774/v2.1/servers/e52bce4c-a98e-4f69-906c-ac6648a2e592"}, {"rel": "bookmark", "href": "http://172.16.29.18:8774/servers/e52bce4c-a98e-4f69-906c-ac6648a2e592"}], "OS-DCF:diskConfig": "AUTO", "progress": 0, "OS-EXT-AZ:availability_zone": "host52", "config_drive": "True", "key_name": null, "OS-SRV-USG:launched_at": "2026-10-08T03:53:57.000000", "OS-SRV-USG:terminated_at": null, "security_groups": [{"name": "default"}], "OS-EXT-STS:task_state": null, "OS-EXT-STS:vm_state": "active", "OS-EXT-STS:power_state": 1, "os-extended-volumes:volumes_attached": [{"id": "591f37c4-e2fc-4dfe-a51e-65bba0e2f829"}]}}"#;

    /// Regression (caught on a second real cloud): the T_3741 body must decode
    /// and yield its address — including the `"image": ""` quirk.
    #[test]
    fn real_cloud_envelope_with_empty_image_string_decodes_and_selects() {
        let parsed: ServerResponse =
            serde_json::from_str(REAL_ENVELOPE_T3741).expect("T_3741 envelope decodes");
        let server = parsed.into_server();

        assert_eq!(
            server.id.as_deref(),
            Some("e52bce4c-a98e-4f69-906c-ac6648a2e592")
        );
        assert_eq!(
            server
                .addresses
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["NET3741"],
            "`addresses` must not come back empty (that was the bug)"
        );
        assert_eq!(
            server.image_id(),
            None,
            "`image: \"\"` means 'no image', it must not poison the decode"
        );

        let got = select_address(
            &server.addresses,
            &server.access_ips(),
            &AddressSelection {
                network: "NET3741",
                family: AddressFamily::IPv4,
                prefer: IpPrefer::Fixed,
                on_ambiguous: OnAmbiguous::Reject,
            },
        )
        .expect("T_3741 instance resolves");
        assert_eq!(got, "172.16.41.62".parse::<IpAddr>().unwrap());
    }

    /// `server.image` in every form seen in the wild. Only the object carries
    /// an id; the rest mean "no image" and must never fail the decode.
    #[test]
    fn image_is_accepted_in_every_form_real_clouds_send() {
        let with_id: NovaServer =
            serde_json::from_str(r#"{"image":{"id":"img-1"}}"#).expect("object");
        assert_eq!(with_id.image_id(), Some("img-1"));

        for body in [
            r#"{"image":null}"#,    // documented "deleted image"
            r#"{"image":""}"#,      // T_3741: the empty-string form
            r#"{"image":"img-1"}"#, // a bare string is not an object we model
            r#"{"image":42}"#,      // … and neither is this
            r#"{}"#,                // absent key
        ] {
            let server: NovaServer =
                serde_json::from_str(body).unwrap_or_else(|err| panic!("{body}: {err}"));
            assert_eq!(server.image_id(), None, "{body}");
        }
    }

    /// The property the `untagged` dispatch used to break: a type error inside
    /// an envelope must be a **loud** decode failure, never a silently empty
    /// server (empty `addresses` read as `no_network` / `networks=[]`).
    #[test]
    fn a_type_error_inside_an_envelope_fails_loudly_instead_of_empting_the_server() {
        let envelope = r#"{"server":{"id":"e52bce4c","addresses":"not-a-map"}}"#;
        assert!(
            serde_json::from_str::<ServerResponse>(envelope).is_err(),
            "a broken inner document must not decode"
        );

        let flat = r#"{"id":"x","addresses":"not-a-map"}"#;
        assert!(
            serde_json::from_str::<ServerResponse>(flat).is_err(),
            "a broken flat document must not decode either"
        );

        assert!(
            serde_json::from_str::<ServerResponse>(r#"{"server":null}"#).is_err(),
            "a null wrapper is not a server"
        );

        // An unknown key is still ignored: clouds add fields all the time.
        let ok = serde_json::from_str::<ServerResponse>(
            r#"{"server":{"id":"x","brand_new_field":{"a":1},"addresses":{"n":[{"addr":"10.0.0.1"}]}}}"#,
        )
        .expect("unknown fields stay harmless");
        assert_eq!(
            ok.into_server().addresses["n"][0].addr.as_deref(),
            Some("10.0.0.1")
        );
    }

    // --- backend user mapping (§3.4) --------------------------------------

    fn rule(name: &str, meta: &[(&str, &str)], user: &str) -> BackendUserRule {
        BackendUserRule {
            match_name: name.to_owned(),
            match_metadata: meta
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            user: user.to_owned(),
        }
    }

    fn mapping<'a>(
        key: &'a str,
        rules: &'a [BackendUserRule],
        default: &'a str,
    ) -> UserMapping<'a> {
        UserMapping {
            metadata_key: key,
            rules,
            default,
        }
    }

    #[test]
    fn metadata_beats_rules_and_default() {
        let rules = vec![rule("^web-", &[], "ubuntu")];
        let mut meta = BTreeMap::new();
        meta.insert("iris_ssh_user".to_owned(), "alice".to_owned());
        let choice = map_backend_user(
            &meta,
            "web-1",
            &mapping("iris_ssh_user", &rules, "cloud-user"),
        );
        assert_eq!(choice.user, "alice");
        assert_eq!(choice.source, UserSource::Metadata);
        assert_eq!(choice.rejected_metadata, None);
    }

    #[test]
    fn rules_are_tried_in_declaration_order() {
        let rules = vec![rule("^db-", &[], "postgres"), rule("", &[], "ubuntu")];
        let meta = BTreeMap::new();

        let db = map_backend_user(&meta, "db-1", &mapping("", &rules, "cloud-user"));
        assert_eq!(db.user, "postgres");
        assert_eq!(db.source, UserSource::Rule(0));

        let web = map_backend_user(&meta, "web-1", &mapping("", &rules, "cloud-user"));
        assert_eq!(web.user, "ubuntu");
        assert_eq!(web.source, UserSource::Rule(1));
    }

    #[test]
    fn rule_conditions_are_anded() {
        let rules = vec![rule("^web-", &[("role", "api")], "ubuntu")];
        let mut meta = BTreeMap::new();
        meta.insert("role".to_owned(), "api".to_owned());

        let hit = map_backend_user(&meta, "web-1", &mapping("", &rules, "cloud-user"));
        assert_eq!(hit.user, "ubuntu");

        let mut wrong_role = BTreeMap::new();
        wrong_role.insert("role".to_owned(), "db".to_owned());
        let miss = map_backend_user(&wrong_role, "web-1", &mapping("", &rules, "cloud-user"));
        assert_eq!(miss.user, "cloud-user");
        assert_eq!(miss.source, UserSource::Default);

        // Same metadata, wrong name.
        let miss = map_backend_user(&meta, "db-1", &mapping("", &rules, "cloud-user"));
        assert_eq!(miss.source, UserSource::Default);
    }

    #[test]
    fn exact_names_do_not_match_by_prefix() {
        let rules = vec![rule("web-1", &[], "ubuntu")];
        let meta = BTreeMap::new();
        assert_eq!(
            map_backend_user(&meta, "web-1", &mapping("", &rules, "x")).user,
            "ubuntu"
        );
        assert_eq!(
            map_backend_user(&meta, "web-10", &mapping("", &rules, "x")).source,
            UserSource::Default
        );
    }

    #[test]
    fn invalid_metadata_falls_through_with_a_record_of_what_was_refused() {
        let rules = vec![rule("^web-", &[], "ubuntu")];
        let mut meta = BTreeMap::new();
        meta.insert("iris_ssh_user".to_owned(), "cloud user".to_owned());

        let choice = map_backend_user(
            &meta,
            "web-1",
            &mapping("iris_ssh_user", &rules, "cloud-user"),
        );
        assert_eq!(choice.user, "ubuntu", "the rule still applies");
        assert_eq!(choice.source, UserSource::Rule(0));
        assert_eq!(choice.rejected_metadata.as_deref(), Some("cloud user"));

        // With no rule it lands on the default, still recording the refusal.
        let choice = map_backend_user(
            &meta,
            "db-1",
            &mapping("iris_ssh_user", &rules, "cloud-user"),
        );
        assert_eq!(choice.user, "cloud-user");
        assert_eq!(choice.source, UserSource::Default);
        assert!(choice.rejected_metadata.is_some());
    }

    #[test]
    fn empty_metadata_key_disables_the_metadata_path() {
        let mut meta = BTreeMap::new();
        meta.insert("".to_owned(), "alice".to_owned());
        let choice = map_backend_user(&meta, "x", &mapping("", &[], "cloud-user"));
        assert_eq!(choice.source, UserSource::Default);
    }

    #[test]
    fn user_validation_rejects_whitespace_and_control_characters() {
        assert!(valid_user("cloud-user"));
        assert!(valid_user("ubuntu"));
        assert!(!valid_user(""));
        assert!(!valid_user(" cloud-user"));
        assert!(!valid_user("cloud user"));
        assert!(!valid_user("cloud\nuser"));
        assert!(!valid_user("cloud\tuser"));
    }
}
