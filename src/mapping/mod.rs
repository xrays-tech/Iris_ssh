//! Simple mapping mode: a static, operator-authored `username → target` table.
//!
//! Pure core of plan-mapping §6.3. A `MappingTable` is loaded once at boot
//! (fail-closed) from a TOML file and served through the standard
//! [`crate::resolve::ControlPlaneClient`] boundary by `MappingClient`, so the
//! generic resolver's cache/breaker/failure-isolation wiring applies unchanged
//! when this client is wrapped in a resolver (Phase 2).
//!
//! `resolve` is a pure in-memory lookup and never touches the network — that is
//! what keeps the pre-auth probe network-free (plan-mapping §2.6 / §6.2). A
//! miss (or an unparseable principal) is `ControlError::NotFound`, the uniform
//! refusal shape the resolver already handles.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;

use crate::error::ConfigError;
use crate::resolve::{ControlError, ControlPlaneClient};
use crate::types::{
    parse_principal, Principal, Policy, ResolveRequest, ResolveResponse, Target,
};

/// Load-time cap on the mapping file: the whole file is parsed at boot, so an
/// unbounded file is a boot-time memory foot-gun.
const MAX_MAPPING_FILE_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB

/// A validated mapping entry: the backend coordinates a principal's sessions
/// dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingEntry {
    /// Backend host: IP or resolvable hostname. Only this operator-authored
    /// value is ever dialed; the client username is never interpolated into
    /// it (design red line 4).
    pub host: String,
    /// Backend port (1..=65535), default 22.
    pub port: u16,
    /// Backend login user (grant.target.user), default = username.
    pub user: String,
}

impl MappingEntry {
    /// The backend coordinates this entry routes to.
    pub fn target(&self) -> Target {
        Target {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
        }
    }
}

/// On-disk shape of one `[[entries]]` row, before validation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    username: String,
    host: String,
    port: Option<u16>,
    user: Option<String>,
}

/// Top-level TOML document: `{ entries = [...] }`. `entries` is optional so a
/// file with no entries at all still parses as an (empty) table.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMappingDoc {
    entries: Option<Vec<RawEntry>>,
}

/// The loaded, validated, immutable mapping table: `username → target`.
#[derive(Debug, Clone)]
pub struct MappingTable {
    entries: HashMap<Principal, MappingEntry>,
}

impl MappingTable {
    /// Read, validate and build the table from `path`.
    ///
    /// A single call does the whole boot gate: missing/unreadable file,
    /// symlink rejection, group/other-write permission gate, size cap, TOML
    /// format and per-entry validation. Any failure is a fail-closed
    /// [`ConfigError`] that refuses the gateway boot; there is no per-session
    /// re-read and no TOCTOU (the table is immutable in memory).
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        // Symlink check first: a symlink may point anywhere, or be swapped out
        // from under the gateway between this check and the later read.
        let metadata = std::fs::symlink_metadata(path).map_err(|source| ConfigError::Invalid {
            field: "mapping_file".into(),
            reason: format!("mapping file {path:?} is not readable: {source}"),
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ConfigError::Invalid {
                field: "mapping_file".into(),
                reason: format!(
                    "mapping file {path:?} is a symlink (refusing: it may point anywhere or be swapped)"
                ),
            });
        }
        // Permission gate: the table is authorization-relevant, so group or
        // other must not be able to write it (0o022). We deliberately do NOT
        // mirror the key files' 0o077 secret mask (backend/mod.rs): a
        // world-READABLE table is operationally harmless, but a
        // group/other-WRITABLE one lets any local user add a routing entry.
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(ConfigError::Invalid {
                field: "mapping_file".into(),
                reason: format!(
                    "mapping file {path:?} is writable by group or other (mode {:o}); expected at most 0o644",
                    mode & 0o777
                ),
            });
        }
        // Boot-time size cap: the file is parsed in full, so refuse absurd
        // sizes before paying for the memory.
        if metadata.len() > MAX_MAPPING_FILE_BYTES {
            return Err(ConfigError::Invalid {
                field: "mapping_file".into(),
                reason: format!(
                    "mapping file {path:?} is {} bytes, exceeding the 4 MiB load cap",
                    metadata.len()
                ),
            });
        }
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Invalid {
            field: "mapping_file".into(),
            reason: format!("mapping file {path:?} is not readable: {source}"),
        })?;
        let doc: RawMappingDoc = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        let raw_entries = doc.entries.unwrap_or_default();
        let mut table = HashMap::with_capacity(raw_entries.len());
        for raw in raw_entries {
            // The username must already be a wire-routable opaque token, so
            // every key that could route is actually reachable (design §4).
            let principal = parse_principal(&raw.username).map_err(|error| ConfigError::Invalid {
                field: "mapping_file".into(),
                reason: format!(
                    "mapping entry username {:?} is not a valid principal: {}",
                    raw.username, error
                ),
            })?;
            let entry = validate_entry(&raw, &principal)?;
            // Duplicate usernames are a load error: the destination would be
            // ambiguous (design §4).
            if table.insert(principal, entry).is_some() {
                return Err(ConfigError::Invalid {
                    field: "mapping_file".into(),
                    reason: format!(
                        "duplicate username {:?} in mapping file (ambiguous destination)",
                        raw.username
                    ),
                });
            }
        }
        Ok(MappingTable { entries: table })
    }

    /// Look up a principal's entry.
    pub fn get(&self, principal: &Principal) -> Option<&MappingEntry> {
        self.entries.get(principal)
    }

    /// Number of mapped users.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table has no entries (every user would be refused).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Validate one raw entry against the mapping-file rules (design §4).
fn validate_entry(raw: &RawEntry, principal: &Principal) -> Result<MappingEntry, ConfigError> {
    let invalid = |field: &str, reason: &str| {
        ConfigError::Invalid {
            field: "mapping_file".into(),
            reason: format!("mapping entry {:?}: {} is {}", raw.username, field, reason),
        }
    };

    if raw.host.is_empty() {
        return Err(invalid("host", "must not be empty"));
    }
    if raw
        .host
        .bytes()
        .any(|b| b == b'\0' || b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(invalid(
            "host",
            "must not contain a control character, whitespace or NUL",
        ));
    }
    let port = raw.port.unwrap_or(22);
    if !(1..=65535).contains(&port) {
        return Err(invalid(
            "port",
            &format!("must be in 1..=65535, got {}", port),
        ));
    }
    // The user defaults to the principal, which the grammar already
    // guarantees non-empty; the explicit check only guards `user = ""`.
    let user = raw.user.clone().unwrap_or_else(|| principal.as_str().to_owned());
    if user.is_empty() {
        return Err(invalid("user", "must not be empty"));
    }
    Ok(MappingEntry {
        host: raw.host.clone(),
        port,
        user,
    })
}

/// A control-plane-style client backed by an in-memory [`MappingTable`].
///
/// Wrapping this in the generic resolver (plan-mapping §6.3) keeps the
/// per-source shape (own cache + single-flight + breaker) identical to the
/// HTTP control plane and OpenStack routes.
#[derive(Debug, Clone)]
pub struct MappingClient {
    table: Arc<MappingTable>,
    /// Whether mapped sessions are recorded (plan-mapping §4.2; wired from
    /// `[mapping] recording` in Phase 2). Per-grant: this value flows
    /// into every `Policy` this client serves.
    recording: bool,
}

impl MappingClient {
    pub fn new(table: Arc<MappingTable>, recording: bool) -> Self {
        MappingClient { table, recording }
    }

    /// Look up `req.principal` in the table and map the hit to a
    /// `ResolveResponse` the generic `Resolver` consumes unchanged.
    fn resolve_inner(
        &self,
        req: &ResolveRequest,
    ) -> Result<ResolveResponse, ControlError> {
        // The client's only user-controlled input is the principal, and it must
        // already be a wire-routable opaque token. A parse failure is folded
        // into `NotFound`: it is the same uniform refusal shape as a table
        // miss (design §5), and nothing in the mapping file is ever dialed
        // from an unvalidated input.
        let principal = Principal::parse(&req.principal).map_err(|_| ControlError::NotFound)?;
        match self.table.get(&principal) {
            Some(entry) => {
                tracing::debug!(
                    target: "mapping",
                    principal = principal.as_str(),
                    client_ip = %req.client_ip,
                    reason = "ok",
                    host = %entry.host,
                    port = entry.port,
                    "mapping hit"
                );
                // The mapping grant's only credential is the forwarded agent
                // identity (design red line 3), hence agent_forwarding = true.
                Ok(ResolveResponse {
                    target: entry.target(),
                    policy: Policy {
                        agent_forwarding: true,
                        recording: self.recording,
                        ttl: 0,
                    },
                })
            }
            None => {
                tracing::debug!(
                    target: "mapping",
                    principal = %req.principal,
                    client_ip = %req.client_ip,
                    reason = "not_found",
                    "mapping miss"
                );
                Err(ControlError::NotFound)
            }
        }
    }
}

impl ControlPlaneClient for MappingClient {
    fn resolve<'a>(
        &'a self,
        req: &'a ResolveRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<ResolveResponse, ControlError>>
                + Send
                + 'a,
        >,
    > {
        let result = self.resolve_inner(req);
        Box::pin(async move { result })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use crate::types::ResolveSource;

    /// Deterministic-enough nonce for unique temp paths in tests
    /// (same style as backend/mod.rs).
    fn unique_nonce(seed: &str) -> u64 {
        seed.len() as u64
            + std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64)
                .unwrap_or(0)
    }

    /// A temp file that removes itself on drop.
    struct TempFile(PathBuf);

    impl TempFile {
        fn create(name: &str, content: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sshgw-mapping-{}-{}-{}",
                std::process::id(),
                name,
                unique_nonce(name)
            ));
            std::fs::write(&path, content).unwrap();
            TempFile(path)
        }

        fn create_with_mode(name: &str, mode: u32, content: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sshgw-mapping-{}-{}-{}",
                std::process::id(),
                name,
                unique_nonce(name)
            ));
            {
                let file = std::fs::File::create(&path).unwrap();
                let _ = file.set_permissions(PermissionsExt::from_mode(mode));
            }
            std::fs::write(&path, content).unwrap();
            TempFile(path)
        }

        /// A sparse file of exactly `size` bytes (sparse on most filesystems).
        fn create_sparse(name: &str, size: u64) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sshgw-mapping-{}-{}-{}",
                std::process::id(),
                name,
                unique_nonce(name)
            ));
            let file = std::fs::File::create(&path).unwrap();
            file.set_len(size).unwrap();
            TempFile(path)
        }

        fn create_bytes(name: &str, bytes: &[u8]) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sshgw-mapping-{}-{}-{}",
                std::process::id(),
                name,
                unique_nonce(name)
            ));
            std::fs::write(&path, bytes).unwrap();
            TempFile(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn entry_toml(username: &str, host: &str, port: Option<u16>, user: Option<&str>) -> String {
        let mut toml = String::from("[[entries]]\n");
        toml.push_str(&format!("username = {:?}\n", username));
        toml.push_str(&format!("host = {:?}\n", host));
        if let Some(p) = port {
            toml.push_str(&format!("port = {}\n", p));
        }
        if let Some(u) = user {
            toml.push_str(&format!("user = {:?}\n", u));
        }
        toml
    }

    #[test]
    fn loads_a_valid_table_and_applies_defaults() {
        // First entry: explicit values. Second: port and user omitted → defaults
        // (port 22, user = username).
        let content = entry_toml("alex", "10.0.0.7", Some(22), Some("alex"))
            + &entry_toml("bob", "203.0.113.10", None, None);
        let temp = TempFile::create("happy-path", &content);
        let table = MappingTable::load(temp.path()).expect("valid table loads");

        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());

        let p_alex = Principal::parse("alex").unwrap();
        let e_alex = table.get(&p_alex).expect("alex mapped");
        assert_eq!(e_alex.host, "10.0.0.7");
        assert_eq!(e_alex.port, 22);
        assert_eq!(e_alex.user, "alex");

        let p_bob = Principal::parse("bob").unwrap();
        let e_bob = table.get(&p_bob).expect("bob mapped");
        assert_eq!(e_bob.host, "203.0.113.10");
        assert_eq!(e_bob.port, 22, "port omitted → default 22");
        assert_eq!(e_bob.user, "bob", "user omitted → default = username");

        let target = e_bob.target();
        assert_eq!(
            target,
            Target {
                host: "203.0.113.10".into(),
                port: 22,
                user: "bob".into()
            }
        );

        // Unknown principal misses cleanly.
        let p_unknown = Principal::parse("unknown").unwrap();
        assert!(table.get(&p_unknown).is_none());
    }

    #[test]
    fn duplicate_username_is_a_load_error() {
        let content = entry_toml("alex", "10.0.0.7", None, None)
            + &entry_toml("alex", "10.0.0.9", None, None);
        let temp = TempFile::create("duplicate", &content);
        let err = MappingTable::load(temp.path()).unwrap_err();
        assert!(
            err.to_string().contains("duplicate username"),
            "expected a duplicate rejection, got: {err}"
        );
    }

    #[test]
    fn invalid_principal_username_is_a_load_error() {
        let cases = ["Bad", "-lead", "has space", ""];
        for username in cases {
            let content = entry_toml(&username, "10.0.0.7", None, None);
            let temp = TempFile::create("bad-principal", &content);
            let err = MappingTable::load(temp.path()).unwrap_err();
            assert!(
                err.to_string().contains("is not a valid principal"),
                "expected a principal rejection for {:?}, got: {err}",
                username
            );
        }
    }

    #[test]
    fn bad_hosts_are_load_errors() {
        let bad_hosts = ["bad\rbhost", "has space", ""];
        for host in bad_hosts {
            let content = entry_toml("a1", host, None, None);
            let temp = TempFile::create("bad-host", &content);
            let err = MappingTable::load(temp.path()).unwrap_err();
            assert!(
                err.to_string().contains("host is"),
                "expected a host rejection for {:?}, got: {err}",
                host
            );
        }
    }

    #[test]
    fn bad_ports_are_load_errors() {
        // port = 0: parses as u16, fails the 1..=65535 range validation.
        let content = entry_toml("a1", "1.2.3.4", Some(0), None);
        let temp = TempFile::create("port-0", &content);
        let err = MappingTable::load(temp.path()).unwrap_err();
        assert!(
            err.to_string().contains("must be in 1..=65535"),
            "expected a port rejection, got: {err}"
        );

        // port = 65536: fails u16 deserialization; still a fail-closed load error.
        // (Written by hand because 65536 does not fit in a u16 literal.)
        let content = "[[entries]]\nusername = \"a1\"\nhost = \"1.2.3.4\"\nport = 65536\n";
        let temp = TempFile::create("port-65536", content);
        assert!(MappingTable::load(temp.path()).is_err());
    }

    #[test]
    fn unknown_fields_are_load_errors() {
        // Unknown field inside an entry.
        let content = "[[entries]]\nusername = \"a1\"\nhost = \"1.2.3.4\"\nextra = 1\n";
        let temp = TempFile::create("unknown-entry-field", content);
        assert!(MappingTable::load(temp.path()).is_err());

        // Unknown field at the document level.
        let content = "bogus = 1\n[[entries]]\nusername = \"a1\"\nhost = \"1.2.3.4\"\n";
        let temp = TempFile::create("unknown-doc-field", content);
        assert!(MappingTable::load(temp.path()).is_err());
    }

    #[test]
    fn missing_file_is_a_load_error() {
        // A path that was never created: the load must fail closed.
        let path = std::env::temp_dir().join(format!(
            "sshgw-mapping-{}-missing-{}",
            std::process::id(),
            unique_nonce("missing")
        ));
        assert!(!path.exists(), "test path must not exist");
        let err = MappingTable::load(&path).unwrap_err();
        assert!(
            err.to_string().contains("is not readable"),
            "expected a missing-file rejection, got: {err}"
        );
    }

    #[test]
    fn empty_table_loads_ok() {
        // `entries = []` …
        let temp = TempFile::create("empty-1", "entries = []\n");
        let table = MappingTable::load(temp.path()).expect("empty entries = [] loads");
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        // … or a file with no `entries` key at all.
        let temp = TempFile::create("empty-2", "# no entries\n");
        let table = MappingTable::load(temp.path()).expect("entries-less file loads");
        assert!(table.is_empty());
    }

    #[test]
    fn group_or_other_writable_file_is_rejected() {
        // 0o666: group and other writable → refuse (integrity gate).
        let content = entry_toml("a1", "1.2.3.4", None, None);
        let temp = TempFile::create_with_mode("group-writable", 0o666, &content);
        let err = MappingTable::load(temp.path()).unwrap_err();
        assert!(
            err.to_string().contains("writable by group or other"),
            "expected a permission rejection, got: {err}"
        );

        // 0o022 (other-writable only) also refuses.
        let temp = TempFile::create_with_mode("other-writable", 0o622, &content);
        assert!(MappingTable::load(temp.path()).is_err());
    }

    #[test]
    fn world_readable_file_is_accepted() {
        // The gate is group/other *write* only: world-readable is fine.
        let content = entry_toml("a1", "1.2.3.4", None, None);
        let temp = TempFile::create_with_mode("world-readable", 0o644, &content);
        let table = MappingTable::load(temp.path()).expect("0o644 loads");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn symlink_is_rejected() {
        let target = TempFile::create(
            "symlink-target",
            &entry_toml("a1", "1.2.3.4", None, None),
        );
        let link_path = std::env::temp_dir().join(format!(
            "sshgw-mapping-{}-symlink-{}",
            std::process::id(),
            unique_nonce("symlink-link")
        ));
        symlink(target.path(), &link_path).unwrap();
        let err = MappingTable::load(&link_path).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected a symlink rejection, got: {err}"
        );
        let _ = std::fs::remove_file(&link_path);
    }

    #[test]
    fn oversize_file_is_rejected() {
        // A sparse file just over the cap: refused by the size gate alone.
        let temp = TempFile::create_sparse("oversize", MAX_MAPPING_FILE_BYTES + 1);
        let err = MappingTable::load(temp.path()).unwrap_err();
        assert!(
            err.to_string().contains("exceeding the 4 MiB load cap"),
            "expected a size rejection, got: {err}"
        );

        // A file exactly at the cap must still load: the cap rejects strictly
        // larger files. The content is a single giant comment line so it is
        // valid TOML that parses as an empty table.
        let mut content = vec![b'#'];
        let pad = vec![b' '; MAX_MAPPING_FILE_BYTES as usize - 1];
        content.extend(pad);
        let temp = TempFile::create_bytes("at-cap", &content);
        let table = MappingTable::load(temp.path()).expect("file at the cap loads");
        assert!(table.is_empty());
    }

    #[test]
    fn resolve_source_mapping_renders() {
        assert_eq!(ResolveSource::Mapping.as_str(), "mapping");
        assert_eq!(ResolveSource::Mapping.to_string(), "mapping");
    }

    fn mapping_client(table: MappingTable, recording: bool) -> MappingClient {
        MappingClient::new(Arc::new(table), recording)
    }

    fn req_for(principal: &str) -> ResolveRequest {
        ResolveRequest {
            principal: principal.to_owned(),
            client_ip: "1.2.3.4".to_owned(),
            key_fp: "SHA256:fp".to_owned(),
        }
    }

    #[tokio::test]
    async fn client_hit_resolves_mapped_target_and_policy() {
        let content = entry_toml("alex", "10.0.0.7", Some(2222), Some("svc"));
        let temp = TempFile::create("client-hit", &content);
        let table = MappingTable::load(temp.path()).unwrap();
        let client = mapping_client(table, true);

        let resp = client.resolve(&req_for("alex")).await.expect("hit resolves");
        assert_eq!(
            resp.target,
            Target {
                host: "10.0.0.7".into(),
                port: 2222,
                user: "svc".into()
            }
        );
        assert!(
            resp.policy.agent_forwarding,
            "mapping grants must synthesize agent_forwarding = true"
        );
        assert!(resp.policy.recording, "recording = true must propagate");
        assert_eq!(resp.policy.ttl, 0);
    }

    #[tokio::test]
    async fn client_miss_is_not_found() {
        let content = entry_toml("alex", "10.0.0.7", None, None);
        let temp = TempFile::create("client-miss", &content);
        let table = MappingTable::load(temp.path()).unwrap();
        let client = mapping_client(table, false);

        let err = client.resolve(&req_for("unknown")).await.unwrap_err();
        assert_eq!(err, ControlError::NotFound);
    }

    #[tokio::test]
    async fn client_rejects_invalid_principal_as_not_found() {
        let content = entry_toml("alex", "10.0.0.7", None, None);
        let temp = TempFile::create("client-bad-principal", &content);
        let table = MappingTable::load(temp.path()).unwrap();
        let client = mapping_client(table, false);

        // "UPPER" fails the Principal grammar before the table lookup; it
        // folds into the same uniform refusal as a table miss.
        let err = client.resolve(&req_for("UPPER")).await.unwrap_err();
        assert_eq!(err, ControlError::NotFound);
    }

    #[tokio::test]
    async fn client_propagates_recording_false() {
        let content = entry_toml("alex", "10.0.0.7", None, None);
        let temp = TempFile::create("client-no-recording", &content);
        let table = MappingTable::load(temp.path()).unwrap();
        let client = mapping_client(table, false);

        let resp = client.resolve(&req_for("alex")).await.expect("hit resolves");
        assert!(
            !resp.policy.recording,
            "recording = false must never enable per-grant recording"
        );
        assert!(resp.policy.agent_forwarding);
    }
}
