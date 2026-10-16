//! Pure Nova helpers: response parsing, address selection, backend-user
//! mapping (plan-openstack §3.3 / §3.4).
//!
//! Nothing in this module touches the network or the config file, so every
//! decision that could send a session to the wrong address — or log in as the
//! wrong user — is a plain function with table-driven tests.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Deserializer};

use crate::config::{AddressFamily, AddressKind, BackendUserRule, IpPrefer, OnAmbiguous};

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
/// (volume-backed server, or an image that is gone) — see [`decode_server`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NovaImage {
    pub id: Option<String>,
}

/// The subset of `GET /v2.1/servers/{id}` this gateway uses.
///
/// Built field-by-field by [`decode_server`] — never by a whole-document
/// `Deserialize` (plan-openstack appendix B.2/B.5): every field is extracted
/// independently, so one field of an unexpected type can no longer drag the
/// entire document (and with it the instance's `addresses`) down with it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NovaServer {
    pub id: Option<String>,
    pub name: Option<String>,
    pub addresses: BTreeMap<String, Vec<NovaAddress>>,
    pub metadata: BTreeMap<String, String>,
    pub image: Option<NovaImage>,
    pub access_ipv4: Option<String>,
    pub access_ipv6: Option<String>,
    /// The project the instance lives in. Purely diagnostic: under
    /// `scope = "cross_project"` the gateway is looking at instances from
    /// every project its roles allow, and this says which one it found.
    /// Never used for authorization or address selection.
    pub tenant_id: Option<String>,
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

/// The lenient field extractor failed because the document is not an object at
/// all (a JSON array, a string, `null`): there are no fields to salvage, so
/// this is a decode failure, not a field-level surprise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The root (or the enveloped document) is not a JSON object.
    NotAnObject,
    /// The body is neither `{"servers": [ … ]}` nor a bare array.
    NotAList,
    /// A server in the list carries `addresses` that could not be read.
    UnreadableAddresses,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::NotAnObject => write!(f, "server document is not a JSON object"),
            DecodeError::NotAList => {
                write!(f, "body is neither {{\"servers\":[…]}} nor an array")
            }
            DecodeError::UnreadableAddresses => {
                write!(f, "a server in the list carries unreadable addresses")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// The outcome of decoding one server document field-by-field
/// (plan-openstack appendix B.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeOutcome {
    /// Every field extracted independently; non-critical surprises yield the
    /// field's default rather than an error.
    pub view: NovaServer,
    /// `addresses` was present but nothing usable could be extracted from its
    /// shape. This is *not* "the instance has no addresses" (`no_address`):
    /// it is a body this gateway could not read, and the caller must refuse
    /// loudly (appendix B.3/B.5).
    pub addresses_present_but_unusable: bool,
    /// Names of fields that arrived in an unexpected shape and were dropped
    /// or defaulted — for a `warn!` line, never for the client.
    pub notes: Vec<&'static str>,
}

/// Extract one server document, one field at a time (appendix B.1/B.2).
///
/// The classic v2 envelope (`{"server": {…}}`) and the flat v2.1 document
/// (`{…}`) are both accepted: the effective document is whichever object this
/// finds. Every field is independent — a `null` `name`, a bare-string
/// `image` (project T_3741's `""`), a numeric metadata value: each yields the
/// field's default and is noted, never an error. The only hard failure is a
/// root that is not an object at all.
pub fn decode_server(value: &serde_json::Value) -> Result<DecodeOutcome, DecodeError> {
    let doc = value.get("server").unwrap_or(value);
    if !doc.is_object() {
        return Err(DecodeError::NotAnObject);
    }
    let mut notes = Vec::new();

    let id = string_from_value(doc.get("id"), "id", &mut notes);
    let name = string_from_value(doc.get("name"), "name", &mut notes);
    let metadata = metadata_from_value(doc.get("metadata"), &mut notes);
    let image_id = image_id_from_value(doc.get("image"), &mut notes);
    let access_ipv4 = string_from_value(doc.get("accessIPv4"), "accessIPv4", &mut notes);
    let access_ipv6 = string_from_value(doc.get("accessIPv6"), "accessIPv6", &mut notes);
    let tenant_id = string_from_value(doc.get("tenant_id"), "tenant_id", &mut notes);
    let (addresses, addresses_present_but_unusable) = addr_map_from_value(doc.get("addresses"));

    Ok(DecodeOutcome {
        view: NovaServer {
            id,
            name,
            addresses,
            metadata,
            image: image_id.map(|id| NovaImage {
                id: Some(id.to_owned()),
            }),
            access_ipv4,
            access_ipv6,
            tenant_id,
        },
        addresses_present_but_unusable,
        notes,
    })
}

/// A JSON string field: `null`/absent means "no value"; anything that is not
/// a string is dropped (and noted) instead of failing the document.
fn string_from_value(
    value: Option<&serde_json::Value>,
    field: &'static str,
    notes: &mut Vec<&'static str>,
) -> Option<String> {
    match value {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(raw)) => Some(raw.clone()),
        Some(_) => {
            notes.push(field);
            None
        }
    }
}

/// `server.image` in every form real clouds send (appendix B.2): only an
/// object carries an id; `null`, `""` (project T_3741), a bare id string, a
/// number … all mean "no image" and must never fail the document.
fn image_id_from_value<'a>(
    value: Option<&'a serde_json::Value>,
    notes: &mut Vec<&'static str>,
) -> Option<&'a str> {
    match value? {
        serde_json::Value::Null => None,
        serde_json::Value::Object(image) => match image.get("id") {
            Some(serde_json::Value::String(id)) => Some(id),
            // An object without a usable id is "no image", harmlessly.
            _ => None,
        },
        _ => {
            notes.push("image");
            None
        }
    }
}

/// `server.metadata`, leniently (appendix B.2): `null` is empty; scalar
/// values (numbers, booleans) are stringified, because operators do label
/// instances with `{"count": 3}`; anything else is dropped and noted.
fn metadata_from_value(
    value: Option<&serde_json::Value>,
    notes: &mut Vec<&'static str>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(value) = value else { return out };
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                match value {
                    serde_json::Value::String(raw) => {
                        out.insert(key.clone(), raw.clone());
                    }
                    serde_json::Value::Number(number) => {
                        out.insert(key.clone(), number.to_string());
                    }
                    serde_json::Value::Bool(flag) => {
                        out.insert(key.clone(), flag.to_string());
                    }
                    // A nested object/array is not a login name; drop it.
                    _ => notes.push("metadata"),
                }
            }
        }
        _ => notes.push("metadata"),
    }
    out
}

/// `server.addresses`, shape-aware (plan-openstack appendix B.3).
///
/// Returns `(map, unusable)`:
///
/// - missing / `null` → `({}, false)` — the field is simply gone;
/// - `{}`             → `({}, false)` — a real instance with no addresses,
///   which resolves to `no_address` (legal, not an error);
/// - a map            → per-network, per-entry lenient extraction; a non-empty
///   map that yields **no** parseable address at all is `unusable=true`,
///   because "structure we could not read" and "an instance with no
///   addresses" must never look the same (this is the direct antidote to the
///   two silent-empty incidents, 2963e76 and 0f30b01);
/// - anything else (a string, an array, a number) → `({}, true)`.
fn addr_map_from_value(
    value: Option<&serde_json::Value>,
) -> (BTreeMap<String, Vec<NovaAddress>>, bool) {
    let Some(value) = value else {
        return (BTreeMap::new(), false);
    };
    match value {
        serde_json::Value::Null => (BTreeMap::new(), false),
        serde_json::Value::Object(networks) => {
            if networks.is_empty() {
                // An empty map is a legitimate "this instance has no
                // addresses" answer (the `case_openstack_no_address` shape).
                return (BTreeMap::new(), false);
            }
            let mut out = BTreeMap::new();
            let mut raw_entries = 0usize;
            for (network, value) in networks {
                let entries = match value {
                    serde_json::Value::Array(items) => {
                        raw_entries += items.len();
                        items.as_slice()
                    }
                    // A single object where a list is documented: one entry.
                    single @ serde_json::Value::Object(_) => {
                        raw_entries += 1;
                        std::slice::from_ref(single)
                    }
                    // A network whose value is not a list at all: unreadable.
                    _ => continue,
                };
                let parsed: Vec<NovaAddress> = entries
                    .iter()
                    .filter_map(|entry| match entry {
                        serde_json::Value::Object(_) => {
                            serde_json::from_value::<NovaAddress>(entry.clone()).ok()
                        }
                        // Extreme defence: some API-compat layers flatten an
                        // entry down to the bare IP literal. The literal is
                        // what would be dialed, so honour it (appendix B.3).
                        serde_json::Value::String(raw) => Some(NovaAddress {
                            addr: Some(raw.clone()),
                            version: None,
                            addr_type: None,
                        }),
                        _ => None,
                    })
                    .collect();
                if !parsed.is_empty() {
                    out.insert(network.clone(), parsed);
                }
            }
            // Entries existed but none of them yielded a dialable address:
            // loud, not silently empty (appendix B.3/B.5).
            let unusable = raw_entries > 0 && candidates(&out).is_empty();
            (out, unusable)
        }
        _ => (BTreeMap::new(), true),
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
/// Caught the hard way against a real cloud: decoding the envelope as a bare
/// server loses `addresses`, so `[openstack] network` matched nothing and the
/// lookup died with the misleading `reason="no_network"` — while the very same
/// request via curl returned the addresses just fine. Accept both shapes so a
/// wire-format difference can never again masquerade as a configuration error.
///
/// The shape is picked by [`decode_server`] (does the document carry a
/// `server` key?), which then extracts every field independently — so a type
/// surprise anywhere inside either shape surfaces as a *field-level* note (or
/// the `addresses_present_but_unusable` flag) instead of silently emptying
/// the document. That is how a second real cloud (project T_3741,
/// `"image": ""`) went dark, and why it cannot again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerResponse {
    /// The extracted document, whichever shape it arrived in.
    pub server: NovaServer,
    /// See [`DecodeOutcome::addresses_present_but_unusable`]: the caller must
    /// refuse loudly (`reason="unparseable"`) rather than dial nothing.
    pub addresses_present_but_unusable: bool,
    /// See [`DecodeOutcome::notes`].
    pub notes: Vec<&'static str>,
}

impl<'de> Deserialize<'de> for ServerResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        decode_server(&value)
            .map(|outcome| ServerResponse {
                server: outcome.view,
                addresses_present_but_unusable: outcome.addresses_present_but_unusable,
                notes: outcome.notes,
            })
            .map_err(serde::de::Error::custom)
    }
}

impl ServerResponse {
    /// The enclosed [`NovaServer`], whichever shape it arrived in.
    pub fn into_server(self) -> NovaServer {
        self.server
    }
}

/// The body of `GET /v2.1/servers?name=…` (plan-openstack appendix A.2).
///
/// The documented shape is `{"servers":[ … ]}`; some API-compat layers answer
/// with a bare array instead. Elements are *bare* server documents — never
/// enveloped — so each one is decoded by the same rules as a single-server
/// body. A 200 whose body is neither shape is a decode failure, never an
/// empty list: "zero instances" and "a body we could not read" must not look
/// the same to the caller.
pub struct ServerList {
    pub servers: Vec<NovaServer>,
}

/// Decode a `GET /servers?name=…` body (plan-openstack appendix B.6).
///
/// The documented shape is `{"servers":[ … ]}`; some API-compat layers answer
/// with a bare array. Elements are *bare* server documents — never enveloped —
/// so each one goes through [`decode_server`]. A 200 whose body is neither
/// shape is a decode failure, never an empty list: "zero instances" and "a
/// body we could not read" must not look the same to the caller.
pub fn decode_server_list(value: &serde_json::Value) -> Result<Vec<NovaServer>, DecodeError> {
    let array = value.get("servers").unwrap_or(value);
    let items = array.as_array().ok_or(DecodeError::NotAList)?;
    items
        .iter()
        .map(|item| {
            let outcome = decode_server(item)?;
            // An element whose `addresses` could not be read is a body we do
            // not understand: fail the list loudly (the caller logs
            // `reason="decode"`) instead of carrying a silently empty
            // instance into the exact-match filter and then dialing nothing
            // (appendix B.5: no silent emptying, ever).
            if outcome.addresses_present_but_unusable {
                return Err(DecodeError::UnreadableAddresses);
            }
            Ok(outcome.view)
        })
        .collect()
}

impl<'de> Deserialize<'de> for ServerList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        decode_server_list(&value)
            .map(|servers| ServerList { servers })
            .map_err(serde::de::Error::custom)
    }
}

/// A structural summary of a response body, safe to log (plan-openstack
/// appendix B.4 / red line 5: never the body itself — it can carry tenant
/// names, IPs and other data an operator's log pipeline should not receive).
///
/// Top-level keys, whether a `server` key is present, the JSON type of
/// `addresses`, the number of networks, and the body length as reported by
/// the transport (`0` when the server did not send a Content-Length). Enough
/// to tell "envelope vs flat", "addresses was a string", or "a 200 with an
/// empty body" apart at a glance — never enough to reconstruct the instance.
pub fn summarize_body(value: &serde_json::Value, raw_len: usize) -> String {
    let mut keys: Vec<&str> = value
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    // A cloud may add dozens of keys; the log line stays bounded.
    let truncated = keys.len() > 12;
    keys.truncate(12);

    let doc = value.get("server").unwrap_or(value);
    let addresses = doc.get("addresses");
    let addresses_type = match addresses {
        None => "missing",
        Some(serde_json::Value::Null) => "null",
        Some(serde_json::Value::Object(_)) => "object",
        Some(serde_json::Value::Array(_)) => "array",
        Some(serde_json::Value::String(_)) => "string",
        Some(serde_json::Value::Number(_)) => "number",
        Some(serde_json::Value::Bool(_)) => "bool",
    };
    let networks = addresses
        .and_then(|value| value.as_object())
        .map(|networks| networks.len())
        .unwrap_or(0);

    format!(
        "keys=[{}{}] has_server={} addresses={} networks={} len={}",
        keys.join(","),
        if truncated { ",…" } else { "" },
        value.get("server").is_some(),
        addresses_type,
        networks,
        raw_len,
    )
}

/// Why a `?name=` lookup did not yield exactly one instance
/// (plan-openstack appendix A.2 / R12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameLookupError {
    /// No server's name equalled the principal.
    NotFound,
    /// More than one server carries that exact name. Nova's filter is a
    /// substring/RE search and instance names are *not* unique, so proceeding
    /// would mean guessing which machine to dial.
    AmbiguousName,
}

impl NameLookupError {
    /// Stable reason token for logs (never shown to the client).
    pub fn reason(self) -> &'static str {
        match self {
            NameLookupError::NotFound => "not_found",
            NameLookupError::AmbiguousName => "ambiguous_name",
        }
    }
}

/// Exact-match filter over a `?name=` result.
///
/// Nova implements `name` as a *substring / regular-expression* search, so the
/// list it returns for `yunqing_dev` can contain `yunqing_dev-2` (and for a
/// plain name can contain anything whose name contains it). Only a
/// byte-for-byte equality counts as "this instance"; everything else is a
/// different machine wearing a similar name.
///
/// Zero matches → [`NameLookupError::NotFound`]; more than one →
/// [`NameLookupError::AmbiguousName`]. Never guess: two machines sharing a name
/// is common enough in rented GPU fleets that picking the first would be a
/// silent wrong-machine connection.
pub fn exact_name_match(
    servers: Vec<NovaServer>,
    name: &str,
) -> Result<NovaServer, NameLookupError> {
    let mut hits = servers
        .into_iter()
        .filter(|server| server.name.as_deref() == Some(name));
    let first = hits.next().ok_or(NameLookupError::NotFound)?;
    if hits.next().is_some() {
        return Err(NameLookupError::AmbiguousName);
    }
    Ok(first)
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
    /// A strict `address_kind` filter (`"floating"` / `"fixed"`) left no
    /// candidate. Deliberately distinct from `NoAddress`: a kind filter is a
    /// policy refusal (the instance *has* addresses, none dialable under the
    /// configured policy) whereas `NoAddress` means nothing was advertised.
    /// `mod.rs` maps this to `ControlError::NotFound`, so the client sees the
    /// same refusal either way — the distinction is log-only.
    NoKind,
}

impl SelectionError {
    /// Stable reason token used in logs and audit output.
    pub fn reason(self) -> &'static str {
        match self {
            SelectionError::NoAddress => "no_address",
            SelectionError::NoNetwork => "no_network",
            SelectionError::Ambiguous => "ambiguous",
            SelectionError::NoKind => "no_address_kind",
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
    /// Strict address-kind filter (appendix D). `Any` preserves the historical
    /// behaviour exactly; `Floating`/`Fixed` keep only that kind and refuse
    /// when the instance advertises none of it.
    pub kind: AddressKind,
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

    // Appendix D: a strict `address_kind` filter runs *after* the network and
    // family filters but *before* the `access_ips` fallback, so neither the
    // legacy fields nor a mis-ordered filter can smuggle a forbidden kind past
    // the policy. `AccessIPv4/6` carry no `OS-EXT-IPS:type`, so they have no
    // kind and are necessarily excluded when the filter is strict — that is
    // the point: an unknown-kind address must not be dialed on a floating-only
    // network. There is deliberately no fallback to the other kind.
    if sel.kind != AddressKind::Any {
        let want = match sel.kind {
            AddressKind::Floating => AddrKind::Floating,
            AddressKind::Fixed => AddrKind::Fixed,
            AddressKind::Any => unreachable!("guarded above"),
        };
        cands.retain(|c| c.kind == want);
        if cands.is_empty() {
            return Err(SelectionError::NoKind);
        }
    }

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
        kind: AddressKind,
    ) -> AddressSelection<'a> {
        AddressSelection {
            network,
            family,
            prefer,
            on_ambiguous,
            kind,
        }
    }

    fn map(entries: Vec<(String, Vec<NovaAddress>)>) -> BTreeMap<String, Vec<NovaAddress>> {
        entries.into_iter().collect()
    }

    /// Decode one body the way the gateway does: JSON → `decode_server`.
    fn decode(json: &str) -> Result<DecodeOutcome, DecodeError> {
        let value: serde_json::Value = serde_json::from_str(json).expect("valid JSON");
        decode_server(&value)
    }

    #[test]
    fn parses_single_network_single_address() {
        let json = r#"{"addresses":{"private":[{"addr":"10.0.0.7","version":4,"OS-EXT-IPS:type":"fixed"}]}}"#;
        let server = decode(json).expect("decodes").view;
        assert_eq!(server.addresses.len(), 1);
        let got = select_address(
            &server.addresses,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
                AddressKind::Any,
            ),
        )
        .expect("one address");
        assert_eq!(got, "10.0.0.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn missing_addresses_field_decodes_as_empty() {
        let server = decode(r#"{"id":"u"}"#).expect("decodes").view;
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
                AddressKind::Any,
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
        let server = decode(json).expect("decodes").view;
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
                AddressKind::Any,
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
                AddressKind::Any,
            ),
        )
        .expect("floating v4 first");
        assert_eq!(got, "192.0.2.10".parse::<IpAddr>().unwrap());

        let got = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Fixed,
                OnAmbiguous::First,
                AddressKind::Any,
            ),
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
                AddressKind::Any,
            ),
        )
        .expect("v6");
        assert_eq!(got, "2001:db8::7".parse::<IpAddr>().unwrap());
    }

    /// Appendix D: with both kinds present, a `floating` filter keeps only the
    /// floating address — so the default `IpPrefer::Floating` cannot be
    /// subverted by a fixed address that happens to sort first.
    #[test]
    fn address_kind_floating_keeps_only_floating_when_both_exist() {
        let addrs = map(vec![
            addr("private", "10.0.0.7", "fixed"),
            addr("public", "192.0.2.10", "floating"),
        ]);

        // `IpPrefer::Fixed` would otherwise pick the fixed address; the kind
        // filter runs after the preference ranking and excludes it.
        let got = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Fixed,
                OnAmbiguous::Reject,
                AddressKind::Floating,
            ),
        )
        .expect("the floating address survives the filter");
        assert_eq!(got, "192.0.2.10".parse::<IpAddr>().unwrap());
    }

    /// Appendix D: an instance with *no* floating address is refused rather
    /// than dialed on its fixed/VXLAN address — the gateway cannot reach it
    /// and a silent fallback would turn a misconfiguration into a hang.
    #[test]
    fn address_kind_floating_refuses_when_only_fixed_addresses_exist() {
        let addrs = map(vec![
            addr("private", "10.0.0.7", "fixed"),
            addr("mgmt", "10.0.1.7", "fixed"),
        ]);

        let err = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
                AddressKind::Floating,
            ),
        )
        .unwrap_err();
        assert_eq!(err, SelectionError::NoKind);
        // Stable reason token — distinct from `no_address`, which means the
        // instance advertised nothing at all.
        assert_eq!(err.reason(), "no_address_kind");
    }

    /// Appendix D: `address_kind = "any"` (the default) is a no-op — a fixed
    /// address is still dialable, exactly as before the knob existed. (With
    /// *both* kinds present and no preference between them the selection is
    /// legitimately ambiguous, so the regression case is a lone fixed address.)
    #[test]
    fn address_kind_any_preserves_the_historical_selection() {
        let addrs = map(vec![addr("private", "10.0.0.7", "fixed")]);

        let got = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::Any,
                IpPrefer::Fixed,
                OnAmbiguous::Reject,
                AddressKind::Any,
            ),
        )
        .expect("a fixed address is still dialable by default");
        assert_eq!(got, "10.0.0.7".parse::<IpAddr>().unwrap());
    }

    /// Appendix D: the filter composes with `on_ambiguous = "reject"` — two
    /// floating addresses under a floating-only policy are still ambiguous,
    /// not "pick one", because the policy says nothing about *which* floating
    /// address to dial.
    #[test]
    fn address_kind_floating_still_rejects_ambiguous_floating_addresses() {
        let addrs = map(vec![
            addr("public", "192.0.2.10", "floating"),
            addr("public2", "192.0.2.11", "floating"),
        ]);

        let err = select_address(
            &addrs,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
                AddressKind::Floating,
            ),
        )
        .unwrap_err();
        assert_eq!(err, SelectionError::Ambiguous);
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
                AddressKind::Any,
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
                AddressKind::Any,
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
                AddressKind::Any,
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
                AddressKind::Any,
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
                AddressKind::Any,
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
                AddressKind::Any,
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
                AddressKind::Any,
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
                AddressKind::Any,
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
                AddressKind::Any,
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
                AddressKind::Any,
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
                AddressKind::Any,
            ),
        )
        .unwrap_err();
        assert_eq!(err, SelectionError::NoAddress);
    }

    #[test]
    fn access_ips_are_parsed_from_both_legacy_fields() {
        let json = r#"{"accessIPv4":"192.0.2.55","accessIPv6":"2001:db8::9"}"#;
        let server = decode(json).expect("decodes").view;
        assert_eq!(
            server.access_ips(),
            vec![
                IpAddr::from([192, 0, 2, 55]),
                "2001:db8::9".parse::<IpAddr>().unwrap()
            ]
        );
        // Garbage is dropped rather than dialed.
        let json = r#"{"accessIPv4":"not-an-ip","accessIPv6":""}"#;
        let server = decode(json).expect("decodes").view;
        assert!(server.access_ips().is_empty());
    }

    /// A **verbatim** `GET /v2.1/servers/{id}` body captured from a real
    /// deployment (`nova_endpoint = 172.16.29.18:8774/v2.1`, instance
    /// `d702cf44-7c17-4410-8ac0-6bd3727fe081`, network `NET3746`), kept as a
    /// file under `tests/fixtures/openstack/servers/` (appendix B.6).
    ///
    /// Note the shape: the resource is wrapped in `{"server": …}`. That is
    /// what the live cloud returned for the *same* request the gateway sends,
    /// and it is why the gateway refused with `reason="no_network"` while
    /// curl showed a perfectly good address.
    const REAL_ENVELOPE: &str =
        include_str!("../../tests/fixtures/openstack/servers/d702cf44_envelope.json");

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
                kind: AddressKind::Any,
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
            // The capture carries a tenant, so the flat sibling must too.
            "tenant_id": "a070dab7800e4eff88ad72e11f864471",
        });
        let flat: ServerResponse = serde_json::from_value(flat).expect("flat decodes");
        let envelope = envelope.into_server();
        let flat = flat.into_server();
        assert_eq!(envelope, flat, "shape must not affect the parsed server");
        // …and the field actually round-tripped, rather than both sides
        // agreeing on "absent".
        assert_eq!(
            envelope.tenant_id.as_deref(),
            Some("a070dab7800e4eff88ad72e11f864471")
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
    const REAL_ENVELOPE_T3741: &str =
        include_str!("../../tests/fixtures/openstack/servers/e52bce4c_envelope_image_empty.json");

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
                kind: AddressKind::Any,
            },
        )
        .expect("T_3741 instance resolves");
        assert_eq!(got, "172.16.41.62".parse::<IpAddr>().unwrap());
    }

    /// `server.image` in every form seen in the wild. Only the object carries
    /// an id; the rest mean "no image" and must never fail the decode — the
    /// non-object forms are noted so the caller can warn (appendix B.2).
    #[test]
    fn image_is_accepted_in_every_form_real_clouds_send() {
        let with_id = decode(r#"{"image":{"id":"img-1"}}"#).expect("object");
        assert_eq!(with_id.view.image_id(), Some("img-1"));
        assert!(
            with_id.notes.is_empty(),
            "the reference shape is not a surprise"
        );

        for (body, noted) in [
            (r#"{"image":null}"#, false),   // documented "deleted image"
            (r#"{}"#, false),               // absent key
            (r#"{"image":""}"#, true),      // T_3741: the empty-string form
            (r#"{"image":"img-1"}"#, true), // a bare string is not an object
            (r#"{"image":42}"#, true),      // … and neither is this
        ] {
            let outcome = decode(body).unwrap_or_else(|err| panic!("{body}: {err:?}"));
            assert_eq!(outcome.view.image_id(), None, "{body}");
            assert_eq!(
                outcome.notes.contains(&"image"),
                noted,
                "image note for {body}: {:?}",
                outcome.notes
            );
        }
    }

    /// The property the old dispatch used to break: a broken `addresses`
    /// shape inside either wire form must surface **loudly** — the
    /// `addresses_present_but_unusable` flag the caller refuses on — never as
    /// a silently empty server (empty `addresses` read as `no_network` /
    /// `networks=[]`). Documents that are not objects at all stay hard
    /// decode failures.
    #[test]
    fn a_broken_addresses_shape_is_loud_not_silently_empty() {
        let envelope = decode(r#"{"server":{"id":"e52bce4c","addresses":"not-a-map"}}"#)
            .expect("the document itself still decodes");
        assert!(envelope.addresses_present_but_unusable);
        assert!(
            envelope.view.addresses.is_empty(),
            "and yields nothing usable"
        );

        let flat = decode(r#"{"id":"x","addresses":"not-a-map"}"#).expect("flat decodes");
        assert!(flat.addresses_present_but_unusable);

        // An array where a map belongs is equally unreadable.
        let array = decode(r#"{"addresses":[1,2,3]}"#).expect("decodes");
        assert!(array.addresses_present_but_unusable);

        // Not an object at all: nothing to salvage, a decode failure.
        assert!(
            serde_json::from_str::<ServerResponse>(r#"{"server":null}"#).is_err(),
            "a null wrapper is not a server"
        );
        assert!(
            serde_json::from_str::<ServerResponse>(r#"[]"#).is_err(),
            "a bare array is not a server document"
        );

        // An unknown key is still ignored: clouds add fields all the time.
        let ok = serde_json::from_str::<ServerResponse>(
            r#"{"server":{"id":"x","brand_new_field":{"a":1},"addresses":{"n":[{"addr":"10.0.0.1"}]}}}"#,
        )
        .expect("unknown fields stay harmless");
        assert!(!ok.addresses_present_but_unusable);
        assert_eq!(
            ok.into_server().addresses["n"][0].addr.as_deref(),
            Some("10.0.0.1")
        );
    }

    /// The appendix B.2 field matrix: every field is independent, so one
    /// surprise cannot drag the document (or another field) down with it.
    #[test]
    fn every_field_decodes_independently_of_its_neighbours() {
        // A name/metadata/image/accessIP surprise next to a perfectly good
        // `addresses` map: the address must still be there.
        let outcome = decode(
            r#"{
                "id": 42,
                "name": 7,
                "metadata": "not-a-map",
                "image": "",
                "accessIPv4": 17,
                "accessIPv6": [],
                "addresses": {"private": [{"addr": "10.0.0.7"}]}
            }"#,
        )
        .expect("decodes");
        assert!(!outcome.addresses_present_but_unusable);
        assert_eq!(
            outcome.view.addresses["private"][0].addr.as_deref(),
            Some("10.0.0.7"),
            "a broken neighbour must not cost the address"
        );
        assert_eq!(outcome.view.id, None, "a numeric id is dropped");
        assert_eq!(outcome.view.name, None, "a non-string name is dropped");
        assert!(outcome.view.metadata.is_empty());
        assert_eq!(outcome.view.image_id(), None);
        assert!(outcome.view.access_ips().is_empty());
        for noted in [
            "id",
            "name",
            "metadata",
            "image",
            "accessIPv4",
            "accessIPv6",
        ] {
            assert!(
                outcome.notes.contains(&noted),
                "{noted} should be noted: {:?}",
                outcome.notes
            );
        }

        // A `null` field is "no value", not a type surprise: no note.
        let outcome = decode(r#"{"id":"x","name":null,"image":null}"#).expect("decodes");
        assert!(outcome.notes.is_empty(), "{:?}", outcome.notes);

        // Metadata scalars are stringified, not dropped (operators do write
        // `{"count": 3}`); nested structures are dropped and noted.
        let outcome =
            decode(r#"{"metadata":{"user":"alice","restarts":3,"retired":true,"tags":["a"]}}"#)
                .expect("decodes");
        assert_eq!(
            outcome.view.metadata.get("user").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            outcome.view.metadata.get("restarts").map(String::as_str),
            Some("3")
        );
        assert_eq!(
            outcome.view.metadata.get("retired").map(String::as_str),
            Some("true")
        );
        assert!(!outcome.view.metadata.contains_key("tags"));
        assert!(outcome.notes.contains(&"metadata"));

        // Only a root that is not an object at all fails.
        for body in [r#""nova""#, r#"7"#, r#"[]"#, r#"null"#] {
            let value: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(
                decode_server(&value),
                Err(DecodeError::NotAnObject),
                "{body}"
            );
        }
    }

    /// The appendix B.3 shape matrix for `addresses`: "gone", "legitimately
    /// empty" and "unreadable" are three different answers (R13).
    #[test]
    fn addresses_shapes_distinguish_gone_empty_and_unreadable() {
        // Gone: missing or null — no_address later, not an error.
        for body in [r#"{"id":"x"}"#, r#"{"addresses":null}"#] {
            let outcome = decode(body).expect("decodes");
            assert!(!outcome.addresses_present_but_unusable, "{body}");
            assert!(outcome.view.addresses.is_empty(), "{body}");
        }

        // Legitimately empty: the `case_openstack_no_address` shape.
        let outcome = decode(r#"{"addresses":{}}"#).expect("decodes");
        assert!(!outcome.addresses_present_but_unusable);
        assert!(outcome.view.addresses.is_empty());

        // Readable: the documented shape.
        let outcome = decode(
            r#"{"addresses":{"private":[{"addr":"10.0.0.7","version":4,"OS-EXT-IPS:type":"fixed"}]}}"#,
        )
        .expect("decodes");
        assert!(!outcome.addresses_present_but_unusable);

        // Entries exist but none is a dialable address: loud, not empty.
        let outcome = decode(r#"{"addresses":{"private":[{"addr":"not-an-ip","version":4}]}}"#)
            .expect("decodes");
        assert!(outcome.addresses_present_but_unusable);

        // One good network next to an unreadable one keeps the good one.
        let outcome = decode(r#"{"addresses":{"good":[{"addr":"10.0.0.1"}],"bad":"not-a-list"}}"#)
            .expect("decodes");
        assert!(!outcome.addresses_present_but_unusable);
        assert_eq!(
            outcome.view.addresses["good"][0].addr.as_deref(),
            Some("10.0.0.1")
        );

        // IPv6 and missing type/version fields are fine: the literal is what
        // gets dialed, the type is only a preference hint.
        let outcome = decode(r#"{"addresses":{"v6":[{"addr":"2001:db8::7"}]}}"#).expect("decodes");
        assert!(!outcome.addresses_present_but_unusable);
        assert_eq!(outcome.view.addresses["v6"][0].addr_type, None);
    }

    // --- lenient extraction + loud summaries (appendix B.3 / B.4) ---------

    #[test]
    fn bare_string_address_entries_are_honoured_as_ip_literals() {
        // Some API-compat layers flatten an entry down to the bare IP.
        let outcome =
            decode(r#"{"addresses":{"private":["10.0.0.7","2001:db8::7"]}}"#).expect("decodes");
        assert!(!outcome.addresses_present_but_unusable);
        assert_eq!(outcome.view.addresses["private"].len(), 2);
        let got = select_address(
            &outcome.view.addresses,
            &[],
            &selection(
                "",
                AddressFamily::IPv4,
                IpPrefer::Floating,
                OnAmbiguous::Reject,
                AddressKind::Any,
            ),
        )
        .expect("the literal is what gets dialed");
        assert_eq!(got, "10.0.0.7".parse::<IpAddr>().unwrap());

        // Mixing an object entry and a bare string in one network works too.
        let outcome = decode(r#"{"addresses":{"private":[{"addr":"10.0.0.1"},"10.0.0.2"]}}"#)
            .expect("decodes");
        assert!(!outcome.addresses_present_but_unusable);
        assert_eq!(outcome.view.addresses["private"].len(), 2);

        // A bare string that is not an IP is dropped; with nothing else left
        // in the map, that is still the loud "unreadable" answer.
        let outcome = decode(r#"{"addresses":{"private":["not-an-ip"]}}"#).expect("decodes");
        assert!(outcome.addresses_present_but_unusable);
    }

    #[test]
    fn decode_server_list_matches_the_deserialize_entry_point() {
        let value = serde_json::json!({"servers":[{"name":"a"},{"name":"b"}]});
        assert_eq!(
            decode_server_list(&value).expect("documented shape").len(),
            2
        );
        let bare = serde_json::json!([{"name":"a"}]);
        assert_eq!(decode_server_list(&bare).expect("bare array").len(), 1);

        // Neither shape: a decode failure, never an empty list.
        assert_eq!(
            decode_server_list(&serde_json::json!({"error": {"code": 404}})),
            Err(DecodeError::NotAList)
        );
        assert_eq!(
            decode_server_list(&serde_json::json!({"servers": "not-an-array"})),
            Err(DecodeError::NotAList)
        );
        // An element with unreadable addresses fails the whole list loudly.
        let broken = serde_json::json!({"servers": [{"name": "a", "addresses": "not-a-map"}]});
        assert_eq!(
            decode_server_list(&broken),
            Err(DecodeError::UnreadableAddresses)
        );
    }

    #[test]
    fn summarize_body_reports_shape_without_the_body() {
        // The real envelope: has_server, addresses type, network count, length.
        let value: serde_json::Value = serde_json::from_str(REAL_ENVELOPE).expect("fixture");
        let summary = summarize_body(&value, 1234);
        assert!(summary.contains("has_server=true"), "{summary}");
        assert!(summary.contains("addresses=object"), "{summary}");
        assert!(summary.contains("networks=1"), "{summary}");
        assert!(summary.contains("len=1234"), "{summary}");
        // Red line B.7.5: none of the body's data — not the instance id, not
        // the address, not the network name — may appear in the summary.
        assert!(!summary.contains("d702cf44"), "{summary}");
        assert!(!summary.contains("172.16.46.25"), "{summary}");
        assert!(!summary.contains("NET3746"), "{summary}");

        // Flat document, with data that must stay out of the log line.
        let value = serde_json::json!({
            "id": "e52bce4c",
            "metadata": {"iris_ssh_user": "alice"},
            "addresses": {"private": [{"addr": "10.0.0.7"}]}
        });
        let summary = summarize_body(&value, 99);
        assert!(summary.contains("has_server=false"), "{summary}");
        assert!(summary.contains("networks=1"), "{summary}");
        assert!(!summary.contains("alice"), "{summary}");
        assert!(!summary.contains("e52bce4c"), "{summary}");

        // An addresses string reads as `addresses=string`, networks=0 — the
        // shape that used to masquerade as `no_network`.
        let value = serde_json::json!({"id": "x", "addresses": "not-a-map"});
        let summary = summarize_body(&value, 12);
        assert!(summary.contains("addresses=string"), "{summary}");
        assert!(summary.contains("networks=0"), "{summary}");

        // Key listing is bounded: a chatty cloud cannot flood the log.
        let object: serde_json::Map<String, serde_json::Value> = (0..20)
            .map(|i| (format!("k{i:02}"), serde_json::json!(i)))
            .collect();
        let summary = summarize_body(&serde_json::Value::Object(object), 5);
        assert!(summary.contains("k00"), "{summary}");
        assert!(summary.contains("k11"), "{summary}");
        assert!(!summary.contains("k19"), "{summary}");
        assert!(summary.contains('…'), "{summary}");
    }

    // --- captured bodies as compile-time fixtures (appendix B.6) ----------

    /// What a fixture body must produce end-to-end, so "loud vs silently
    /// empty" is a regression assertion rather than a code-reading exercise.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Expect {
        /// Decodes and selects this exact address.
        Resolve(&'static str),
        /// Decodes, and the instance genuinely has no dialable address.
        NoAddress,
        /// `addresses` is present but unreadable — refused loudly.
        Unparseable,
        /// Not a server document at all — a decode failure.
        DecodeError,
    }

    /// One body (a verbatim capture or a constructed variant) and the
    /// selection knobs it is written for: `network` is the configured
    /// `[openstack] network`; every fixture is deterministic under
    /// `family = any`, `prefer = floating`, `on_ambiguous = "reject"`.
    struct Fixture {
        name: &'static str,
        body: &'static str,
        network: &'static str,
        expect: Expect,
    }

    /// The fixture corpus (appendix B.6). The two real captures live in
    /// `tests/fixtures/openstack/servers/` verbatim (including T_3741's
    /// `image: ""`); the constructed variants freeze each shape the lenient
    /// extractor must — or must not — accept.
    const FIXTURES: &[Fixture] = &[
        Fixture {
            name: "d702cf44_envelope",
            body: include_str!("../../tests/fixtures/openstack/servers/d702cf44_envelope.json"),
            network: "NET3746",
            expect: Expect::Resolve("172.16.46.25"),
        },
        Fixture {
            name: "e52bce4c_envelope_image_empty",
            body: include_str!(
                "../../tests/fixtures/openstack/servers/e52bce4c_envelope_image_empty.json"
            ),
            network: "NET3741",
            expect: Expect::Resolve("172.16.41.62"),
        },
        Fixture {
            name: "flat_variant",
            body: include_str!("../../tests/fixtures/openstack/servers/flat_variant.json"),
            network: "private",
            expect: Expect::Resolve("10.0.0.7"),
        },
        Fixture {
            name: "addresses_missing",
            body: include_str!("../../tests/fixtures/openstack/servers/addresses_missing.json"),
            network: "",
            expect: Expect::NoAddress,
        },
        Fixture {
            name: "addresses_null",
            body: include_str!("../../tests/fixtures/openstack/servers/addresses_null.json"),
            network: "",
            expect: Expect::NoAddress,
        },
        Fixture {
            name: "addresses_string",
            body: include_str!("../../tests/fixtures/openstack/servers/addresses_string.json"),
            network: "",
            expect: Expect::Unparseable,
        },
        Fixture {
            name: "addresses_empty_map",
            body: include_str!("../../tests/fixtures/openstack/servers/addresses_empty_map.json"),
            network: "",
            expect: Expect::NoAddress,
        },
        Fixture {
            name: "addresses_dual_network",
            body: include_str!(
                "../../tests/fixtures/openstack/servers/addresses_dual_network.json"
            ),
            network: "private",
            expect: Expect::Resolve("10.0.0.1"),
        },
        Fixture {
            name: "addresses_ipv6",
            body: include_str!("../../tests/fixtures/openstack/servers/addresses_ipv6.json"),
            network: "",
            expect: Expect::Resolve("2001:db8::7"),
        },
        Fixture {
            name: "entry_missing_type",
            body: include_str!("../../tests/fixtures/openstack/servers/entry_missing_type.json"),
            network: "private",
            expect: Expect::Resolve("10.0.0.5"),
        },
        Fixture {
            name: "metadata_null",
            body: include_str!("../../tests/fixtures/openstack/servers/metadata_null.json"),
            network: "private",
            expect: Expect::Resolve("10.0.0.6"),
        },
        Fixture {
            name: "metadata_non_string_values",
            body: include_str!(
                "../../tests/fixtures/openstack/servers/metadata_non_string_values.json"
            ),
            network: "private",
            expect: Expect::Resolve("10.0.0.8"),
        },
        Fixture {
            name: "image_bare_string",
            body: include_str!("../../tests/fixtures/openstack/servers/image_bare_string.json"),
            network: "private",
            expect: Expect::Resolve("10.0.0.9"),
        },
        Fixture {
            name: "root_not_object",
            body: include_str!("../../tests/fixtures/openstack/servers/root_not_object.json"),
            network: "",
            expect: Expect::DecodeError,
        },
    ];

    /// Walk the whole corpus: every body must decode and select exactly what
    /// its fixture says — a captured address, a legal `no_address`, a loud
    /// `unparseable`, or a decode failure. Nothing may "succeed" with an
    /// empty answer the fixture did not ask for.
    #[test]
    fn fixture_bodies_behave_exactly_as_the_corpus_documents() {
        for fixture in FIXTURES {
            let value: serde_json::Value = serde_json::from_str(fixture.body)
                .unwrap_or_else(|err| panic!("{}: not valid JSON: {err}", fixture.name));

            let outcome = match decode_server(&value) {
                Ok(outcome) => outcome,
                Err(err) => {
                    assert_eq!(
                        fixture.expect,
                        Expect::DecodeError,
                        "{}: unexpected decode failure: {err}",
                        fixture.name
                    );
                    continue;
                }
            };

            if fixture.expect == Expect::Unparseable {
                assert!(
                    outcome.addresses_present_but_unusable,
                    "{}: an unreadable addresses shape must be flagged loudly",
                    fixture.name
                );
                continue;
            }
            assert!(
                !outcome.addresses_present_but_unusable,
                "{}: a readable body must not be flagged unusable",
                fixture.name
            );

            let got = select_address(
                &outcome.view.addresses,
                &outcome.view.access_ips(),
                &selection(
                    fixture.network,
                    AddressFamily::Any,
                    IpPrefer::Floating,
                    OnAmbiguous::Reject,
                    AddressKind::Any,
                ),
            );
            match (fixture.expect, got) {
                (Expect::Resolve(want), Ok(got)) => {
                    assert_eq!(
                        got,
                        want.parse::<IpAddr>().expect("fixture ip"),
                        "{}",
                        fixture.name
                    );
                }
                (Expect::NoAddress, Err(SelectionError::NoAddress)) => {}
                (expected, other) => {
                    panic!("{}: expected {expected:?}, got {other:?}", fixture.name)
                }
            }
        }
    }

    // --- name lookup (appendix A.2) ---------------------------------------

    fn servers_from(json: &str) -> Vec<NovaServer> {
        serde_json::from_str::<ServerList>(json)
            .expect("list decodes")
            .servers
    }

    #[test]
    fn server_list_accepts_both_wire_shapes_and_never_fails_silently() {
        // The documented shape.
        assert_eq!(
            servers_from(r#"{"servers":[{"name":"a"},{"name":"b"}]}"#).len(),
            2
        );
        // A bare array, as some API-compat layers answer.
        assert_eq!(servers_from(r#"[{"name":"a"}]"#).len(), 1);
        // A 200 whose body is neither shape is a *decode failure*, never an
        // empty list: "no instances" and "unreadable body" must not look alike.
        assert!(serde_json::from_str::<ServerList>(r#"{"error":{"code":404}}"#).is_err());
        assert!(serde_json::from_str::<ServerList>(r#"{"servers":"not-an-array"}"#).is_err());
    }

    #[test]
    fn exact_name_match_filters_substring_hits_and_refuses_ambiguity() {
        // What Nova actually returns for `?name=web`: a substring superset.
        let servers = servers_from(
            r#"{"servers":[
                {"name":"web","addresses":{"private":[{"addr":"10.0.0.1"}]}},
                {"name":"web-2","addresses":{"private":[{"addr":"10.0.0.2"}]}},
                {"name":"db","addresses":{"private":[{"addr":"10.0.0.3"}]}}
            ]}"#,
        );
        let hit = exact_name_match(servers, "web").expect("exactly one exact hit");
        assert_eq!(hit.name.as_deref(), Some("web"));

        // Substring hits are different machines: NotFound, not "close enough".
        let servers = servers_from(r#"{"servers":[{"name":"web-2"}]}"#);
        assert_eq!(
            exact_name_match(servers, "web").unwrap_err(),
            NameLookupError::NotFound
        );

        // Two exact hits: refuse rather than guess (R12).
        let servers = servers_from(r#"{"servers":[{"name":"web"},{"name":"web"}]}"#);
        assert_eq!(
            exact_name_match(servers, "web").unwrap_err(),
            NameLookupError::AmbiguousName
        );

        // A document with no `name` at all can never match a name lookup.
        let servers = servers_from(r#"{"servers":[{}]}"#);
        assert_eq!(
            exact_name_match(servers, "web").unwrap_err(),
            NameLookupError::NotFound
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
