# Design: Simple Mapping Mode (username → target)

Status: DRAFT (gate G1 pending @oracle review)
Scope: ssh-gateway (Iris_ssh)

## 1. Problem / Goal

Today the gateway resolves a client `username` to a backend target through exactly
two sources, chosen by `ResolveRouter` (src/resolve/router.rs:230):

- `[control_plane]` — external HTTP resolver+authorizer (src/resolve/mod.rs);
- `[openstack]` — OpenStack Nova instance UUID route (src/openstack/mod.rs),
  disabled by default, lab-mode authorization via
  `allow_any_authenticated_key`.

Both require external infrastructure (a control-plane service, or a Nova cloud).

This design adds a **third, local, static routing source**: a *simple mapping mode*.
When enabled through a config switch, the gateway matches the client `username`
against a **mapping file** (path given in config). A match yields the backend target
(host/port/login-user) directly from that file — no control plane, no OpenStack.
No match → the session is refused (fail-closed), consistent with every other route.

This mode is for operators who want a plain, file-driven "this user goes to this
host" table without standing up a control plane or a cloud.

**Mapping is a *pure routing mode*.** While enabled it is the *only* routing
authority: it is mutually exclusive with both `[openstack]` and `[control_plane]`
(a config enabling `[mapping]` together with either is rejected — §3, §6.5). It
never coexists with, nor falls through to, another resolver. `route()` returns
`ResolveRoute::Mapping` for every principal while enabled.

### 1.1 Requirements (user)

1. A config switch toggles the mode on/off.
2. The switch's config names one mapping file.
3. The mapping file maps `username` → target `IP/host`, `port`, (and login user).
4. In this mode, matching is based on the mapping file loaded via config.

## 2. Design constraints drawn from the codebase

1. **Feature-off byte-compatibility (repository red line).** The default
   configuration (no `[mapping]` section, or `[mapping] enabled = false`) must be
   functionally identical to today. All code must be inert while off.
2. **Fail-closed.** A malformed/unparseable mapping file must fail the gateway
   **at startup**, not per-session. A username with no mapping entry must be refused.
3. **One credential path only.** The backend leg has exactly one credential: the
   end user's forwarded ssh-agent (plan-agent-only). Mapping grants therefore
   synthesize `policy.agent_forwarding = true`. The gateway stores no key.
4. **No SSRF / no arbitrary dial from the client.** Mapping targets come only from
   the operator-authored file. The client controls only the `username` key. The
   username is validated against the same `Principal` grammar as today and must
   never be interpolated into the target host string.
5. **Uniform client-visible failure.** A missing/unknown mapping is indistinct from
   every other refusal (the `auth_rejection_pad` timing envelope applies as usual).
6. **Pre-auth probe must never touch the network.** `route()` stays a pure
   computation; for the mapping route it is an in-memory table lookup, so the
   `auth_publickey_offered` probe (server/mod.rs:1255) remains network-free.
7. **Failure-domain isolation.** The mapping resolver is its own `Resolver`
   object (own cache/breaker), like OpenStack (plan-openstack §0-3) — a dead
   control plane can never trip the mapping route, and vice versa.

## 3. Config schema

New optional section `[mapping]` (mirrors `[openstack]`'s optional/inert pattern):

```toml
[mapping]
enabled = true            # the switch. default false (absent section == disabled)
mapping_file = "/etc/ssh-gw/mappings.toml"   # required when enabled

# Authorization semantics (required to be explicit, mirroring [openstack]):
# In mapping mode there is no control plane to authorize a key. Two options,
# chosen by this flag — see §5.
allow_any_authenticated_key = true   # v1: must be true while enabled
```

Validation rules (in `GatewayConfig::parse` two-pass, config.rs:557+):

- `mapping` absent, or present with `enabled = false` → `GatewayConfig.mapping = None`
  (byte-inert).
- `enabled = true` requires `mapping_file` non-empty; config-parse validates the
  **path** only, and the immutable `MappingTable` (format + contents) is loaded
  **once** at `GatewayContext::build_with_clients` (see §4.1 — single-load,
  no TOCTOU). Any failure is a `ConfigError` → gateway refuses to boot (fail-closed).
- `enabled = true` requires `allow_any_authenticated_key = true`. The validator
  flags the pairing explicitly when it is absent, like openstack's validator does
  (config.rs:1436) — there is no other legal value in v1; the flag exists solely as
  the explicit acknowledgement that mapping mode is a lab-style "any key" authority
  (§5).
- `enabled = true` is **mutually exclusive** with `[openstack]` enabled **and**
  with a live `[control_plane]`: a config enabling `[mapping]` together with either
  is a config error (two routing authorities; dead config = lying config). This also
  simplifies `control_plane_required` (config.rs:1229): mapping enabled ⇒ the
  control plane is not required, exactly like `routing = "openstack_only"`.
- `allow_any_authenticated_key` is accepted-but-ignored while `enabled = false`
  (a config that turns the feature back on is never a two-step operation — the same
  philosophy as the openstack section, config.example.toml:105-112).

New structs:

```rust
pub struct MappingConfig {
    pub enabled: bool,
    pub mapping_file: PathBuf,
    /// Explicit acknowledgment of the "any key that passes front-leg
    /// verification may reach any mapped target" authorization model (§5).
    /// Must be `true` while enabled (it is the only legal value in v1).
    pub allow_any_authenticated_key: bool,
    /// Whether mapped sessions are recorded (parity with `[openstack] recording`).
    /// Default false; see §4.2. Because `policy.recording` is per-grant
    /// (server/mod.rs:1149), `false` here means mapped sessions are NEVER recorded
    /// even when `[recording]` is configured.
    pub recording: bool,
}
```

`GatewayConfig` gains: `pub mapping: Option<MappingConfig>`.

## 4. Mapping file format

Format: **TOML** (already a dependency; strict `deny_unknown_fields` = fail-closed
on typos; single-document, parseable at load time).

```toml
# /etc/ssh-gw/mappings.toml
#
# username -> backend target table for "simple mapping mode".
# Treated as authorization-relevant. Keep 0600, root-owned.

[[entries]]
username = "alex"          # required, must satisfy src/types.rs Principal grammar
host = "10.0.0.7"          # required: IP or resolvable hostname (never interpolated)
port = 22                  # optional, default 22
user = "alex"              # optional, default = username (backend login user)
```

Rules:

- `username` — required; must parse via `parse_principal` (src/types.rs:28) so every
  key that could route is actually reachable on the wire. Duplicate usernames in the
  file are a **load error** (ambiguous destination).
- `host` — required; rejects empty, ASCII control characters, whitespace and NUL
  (cheap, fail-closed; prevents opaque dial errors). Only the operator-authored
  value is used; the username is never concatenated into it (red line 4). The
  backend dial (backend/mod.rs:385 `client::connect`) accepts host strings.
- `port` — optional, default 22, validated 1..=65535.
- `user` — optional, default = `username`. Backend login user (grant.target.user).
  This default is safe **only** because the `Principal` grammar
  (`^[a-z0-9][a-z0-9_-]{0,62}$`, src/types.rs:44-54) excludes
  separators/metacharacters, so the interpolation cannot escape the login-user
  field; operators may set an explicit `user` for clarity.
- Unknown fields, non-Toml content, wrong types → load error (fail-closed boot).
- **File permissions (enforced, not advisory):** the mapping file is
  authorization-relevant, so its permissions are checked at load and a violation is
  a fail-closed `ConfigError`, mirroring `check_key_permissions`
  (backend/mod.rs:88-101): reject if the file is writable by group/other
  (`mode & 0o022 != 0`, the same unsafe-mask philosophy), and reject symlinks
  (a symlink may point anywhere / be swapped). Owners may be any uid; the
  permission check (not ownership) is the load-time gate. This closes the local
  privilege-escalation path where any local user adds an entry.
- **Size cap:** the whole file is parsed at boot, so reject files larger than a
  sane bound (e.g. 4 MiB) at load time to avoid a boot-time memory foot-gun.
- An empty table (`entries = []`, or missing `[[entries]]` entirely) is **valid**
  but emits a startup warning (every user is refused).

### 4.1 Load & validation timing

The file is loaded **once, at build time**, not at config-parse time and not
lazily per-session:

- Config-parse validates the *path* (non-empty while enabled) and the config-level
  coherence rules only.
- `MappingTable::load(path) -> Result<MappingTable, ConfigError>` is called exactly
  once in `GatewayContext::build_with_clients` (server/mod.rs:461), reading +
  parsing + validating the whole file into an immutable `HashMap<Principal,
  MappingEntry>` (including permission/size checks above).
- Any error (missing file, bad permissions, symlink, too large, bad Toml, duplicate
  username, invalid principal, bad port) → `ConfigError` → `main.rs` refuses to boot.
  Because the table is immutable in memory, there is no per-session read and no
  TOCTOU window after boot.
- No hot reload in v1 (static routing table; the generic `Resolver`'s small TTL
  leaves room for a future watcher reload). Documented in known-limitations.

### 4.2 Recording

`policy.recording` is **per-grant** (server/mod.rs:1149 sets the channel tap from
`grant.policy.recording`; `[openstack]` maps `recording` at openstack/mod.rs:935).
Mapping honors the same model via `[mapping] recording` (default `false`): setting
it `false` means mapped sessions are **never recorded even when `[recording]` is
configured** — this is explicit and documented (known-limitations), not an implicit
side effect of "global" recording.

## 5. Authorization model (the critical decision)

In this mode there is no control plane and, by default, no Nova scope to act as the
authority. The gateway must still decide **which keys may use a mapping entry**.

Precedent: OpenStack's lab mode reuses `allow_any_authenticated_key = true` —
"any key that passes front-leg verification can reach any reachable-instance the
file/scope grants" (config.rs:1436-1454, openstack/mod.rs:138).

Mapping mode v1 adopts exactly the same model and makes it an **explicit flag**:

- Front leg verification is unchanged (russh verifies the user public
  key/certificate and its signature — server/mod.rs:1287-1334). A CA-backed
  certificate still requires its issuing CA in `[ca]`, its validity window, and its
  principals (server policy).
- `allow_any_authenticated_key = true` means: *given a valid front-leg key and a
  username present in the mapping file, the session is authorized to that target*.
  No additional per-username key pinning in v1. This is the explicit,
  deliberately-alarming acknowledgement, identical in spirit to the openstack flag
  and stated in the config example with the same warnings.
- If `allow_any_authenticated_key` is not true while `enabled = true`, the
  validation **refuses** the config (never silently behave as "any key" nor silently
  refuse everything ambiguous).

Front-leg raw-key acceptance without a CA set: for a raw public key (not a cert),
`auth_publickey` is reached after russh verifies the signature(server/mod.rs:1291).
There is no built-in key store; authorization is exactly `router.authorize`. In
mapping mode that answer = "username in file ∧ allow_any flag". This matches the
openstack lab behavior and keeps the blast radius to *configured usernames only*.

Contract: an entry in the mapping file does **not** by itself authorize a client;
the `allow_any_authenticated_key` flag does. Both must hold. (Fail-closed on both.)

**Startup warnings (mandatory, mirroring openstack/mod.rs:138-144):**
- When `[mapping] allow_any_authenticated_key = true`, emit a `tracing::warn!` on
  `target: "mapping"` at startup: "any key that passes front-leg verification may
  reach any mapped target; no per-username key pinning".
- When the loaded table is empty (or absent), emit a `tracing::warn!` that every
  user will be refused.

There is **no per-username key pinning in v1** — the mapping file grants a
username→target route to any front-leg-valid key. This is the lab-only nature of
the mode; the `allow_any_authenticated_key` flag is its explicit, deliberately
alarming acknowledgment.

## 6. Routing / resolver integration

### 6.1 New variants

- `ResolveSource::Mapping` (src/types.rs:143) with `as_str() -> "mapping"`
  (audit `resolve_source` = "mapping", no schema change needed).
- `ResolveRoute::Mapping` (src/resolve/router.rs:24).

### 6.2 Pure predicate `route_for`

`route_for(principal, routing, openstack_enabled, route_by)` (router.rs:52) stays
the decision table for openstack vs control plane. Mapping is an **independent,
higher-priority input** — not entangled with the openstack `route_by` gate:

- `ResolveRouter` gains `mapping_enabled: bool` and `mapping: Option<Arc<Resolver>>`.
- `route(&self, principal)`:
  - if `mapping_enabled` → `ResolveRoute::Mapping` for *every* principal,
    **unconditionally** (mutual exclusivity in §3 makes this sound; the mapping
    resolver itself distinguishes hit vs miss — matching is "is it in the file?").
  - else → existing `route_for(...)`.
- `can_serve(ResolveRoute::Mapping) = mapping.is_some()`.

Because the resolved route for Mapping is decided entirely in-memory (a table
membership check), the pre-auth probe (`auth_publickey_offered`, server/mod.rs:1280)
never even consults the mapping resolver — its only guard is `route() !=
ControlPlane`, which Mapping satisfies, so it stays strictly network-free. (Precise
wording: the probe performs *no* mapping lookups at all; it only asks `route()`.)

### 6.3 Mapping resolver

New module `src/mapping/mod.rs`:

- `MappingTable` — the loaded, validated immutable table (see §4.1);
  `fn get(&self, principal) -> Option<MappingEntry>`.
- `MappingClient` — implements `resolve::ControlPlaneClient`
  (resolve/mod.rs:174): `resolve(req)` synchronously reads the table;
  hit → `ResolveResponse { target, policy }`; miss → `Err(ControlError::NotFound)`.
- Built at `GatewayContext::build_with_clients` (server/mod.rs:461) like the
  openstack client:
  ```
  let mapping_resolver = MappingConfig-load → MappingTable
      → Option<Arc<Resolver>> // wrapped with the generic resolver for
                              // cache/breaker/failure isolation (§2.7)
  ```
- Wrapping in the generic `Resolver` (resolve/mod.rs:316) is deliberate: it keeps
  the per-source shape identical (own cache + single-flight + breaker), so
  failure-domain isolation (§2.7) holds uniformly — a pathological condition in
  one source can never trip another source's breaker. **Fixed tuning, no new
  knobs:** because the table is immutable in memory and loaded once at boot, it
  can never yield a transient failure, so `fail_open = false`, breaker thresholds
  are the standard ones, and the positive TTL is small (e.g. `cache_ttl` from the
  `[control_plane]`-style default of 30s) purely to leave room for a future
  watcher reload. The breaker/last-known-good paths are vestigial for mapping and
  are kept only for uniformity — this is stated, not hidden behind a failure mode
  that cannot occur.
- Each target stays `policy.agent_forwarding = true` (the only credential path);
  `policy.recording` comes from `[mapping] recording` (§4.2), `ttl` = 0.

### 6.4 `ResolveRouter::authorize`

Add the `ResolveRoute::Mapping` arm:

- source = `ResolveSource::Mapping`;
- calls `mapping` resolver's `authorize(...)`;
- miss → `ResolveError::NotFound` (uniform refusal);
- metrics: mapping resolve latency/ok/err counters (mirror openstack counters,
  §7);
- stamps `grant.resolve_source = ResolveSource::Mapping`.

### 6.5 Simplification of `can_serve`/control-plane wiring in build

`server/mod.rs:571-588` belt-and-braces checks need a mapping branch, and the
control-plane *requirement* logic must be made mapping-aware in **both** places it
lives:

1. **Config validation — `control_plane_required` (config.rs:1229-1240).** Today it
   only exempts `routing = "openstack_only"`. Add: `mapping` enabled ⇒
   `control_plane_required = false` (pure mapping mode needs no control plane). A
   mapping config without `[control_plane]` is then valid at parse time — matching
   the openstack_only precedent. Conversely, `[mapping] enabled` *together with*
   `[control_plane]` present is a config error (two authorities, dead config), and
   `[mapping] enabled` together with `[openstack] enabled` is a config error.

2. **Build — `control_plane_needed` (server/mod.rs:515).** Rewrite as:
   `control_plane_needed = !openstack_enabled && !mapping_enabled || routing == Hybrid`.
   Because mapping configs are mutually exclusive with `[openstack]` present and
   with live `[control_plane]` (validated at parse time), the only way mapping is
   enabled here is with `routing` at its default (`Hybrid`) and no CP — so the
   correct decision is: `mapping_enabled ⇒ control_plane_needed = false`. The
   `routing == Hybrid` disjunct then only ever reflects the openstack-shaped
   configs, so the formula above is coherent: with mapping on and openstack off,
   `!openstack_enabled && !mapping_enabled` is false and `routing == Hybrid`
   would be true — therefore the formula MUST short-circuit on `mapping_enabled`
   first. Concretely: `let control_plane_needed = !mapping_enabled && (!openstack_enabled || routing == Hybrid);`

3. **Belt-and-braces at build (server/mod.rs:571-588):**
   - `if mapping_enabled && !router.can_serve(ResolveRoute::Mapping)` → boot error
     ("[mapping] enabled but its resolver could not be built").
   - `if control_plane_needed && !router.can_serve(ResolveRoute::ControlPlane)` →
     unchanged (now false when mapping is on, so a mapping config never trips it).

## 7. Observability

Mirror the openstack counters (router.rs:341-372, metrics/mod.rs):

- `sshgw_mapping_resolve_total` (ok/err breakdown, or ok/err/total counters)
- `sshgw_mapping_resolve_latency_seconds`
- `sshgw_mapping_hits_total` / `sshgw_mapping_miss_total` (optional but useful:
  a miss is a refused login, worth a count; misses already surface as
  `resolve_source="mapping"` + `reason="not_found"` in the `resolve` tracing target).

Tracing: structured lines on `target: "mapping"` with `source=mapping`,
`reason=not_found|ok`, consistent with the resolve target (router.rs:349-357).

Audit: `resolve_source = "mapping"` flows through `Grant` (types.rs:241) and the
audit record unchanged — no schema change.

## 8. Files touched (plan-level summary)

| Area | File | Change |
|---|---|---|
| types | src/types.rs | `ResolveSource::Mapping`, `as_str()` |
| config | src/config.rs | `RawMapping` / `MappingConfig`, `[mapping]` validation, `GatewayConfig.mapping`, mapping-file load hook |
| mapping (new) | src/mapping/mod.rs | `MappingTable` + `MappingClient` |
| routing | src/resolve/router.rs | `ResolveRoute::Mapping`, `mapping_enabled`, router arm, can_serve, metrics, source stamp |
| build | src/server/mod.rs | build mapping client/resolver, can_serve belt-and-braces, `control_plane_needed` |
| docs | config.example.toml, README.md, docs/ops-runbook.md, docs/known-limitations.md | new `[mapping]` section + warnings |
| tests | unit (config, mapping, router, server) + integration case(s) | §9 |

## 9. Test plan (summary; detailed in dev plan)

1. Config validation: absent/disabled inert; enabled w/o file → error; bad file
   (to, duplicate, bad principal, bad port, unknown field, wrong perms, symlink,
   over size cap) → startup error; `[mapping]`+`[openstack]` both on → error;
   `[mapping]`+`[control_plane]` both on → error; allow-flag requirement;
   `control_plane_required` false when mapping enabled.
2. `MappingTable::load`: happy path, defaults (port/user), duplicates, grammar,
   permission/symlink/size enforcement, empty table.
3. `MappingClient::resolve`: hit → target+policy; miss → NotFound.
4. Router: `route()` → Mapping when enabled (every principal, unconditionally);
   can_serve; authorize hit/miss; source stamp; metrics counters; failure-domain
   isolation (mapping breaker independent of CP).
5. Server build: mapping wiring; belt-and-braces (`control_plane_needed =
   !mapping_enabled && (...)`); pre-auth probe stays network-free for mapping route.
6. Integration (tests/integration + scripts/mock_*): a mapping-mode case driving
   the real binary with a temp mappings.toml + local sshd backend; assert dialed
   target = mapped host/port/user, and unknown user → refused (-8 auth echo).
7. Lint + clippy + full `make test`.

## 10. Open questions — RESOLVED at gate G1

1. `allow_any_authenticated_key` — **keep the explicit flag** (only legal value in
   v1; sole purpose is the explicit acknowledgment that mapping has no per-username
   key pinning). Lab-only mode.
2. Hot reload — **out of scope v1** (static table, loaded once at boot). Documented
   in known-limitations.
3. `[mapping]` mutual exclusion — **extended to both** `[openstack]` **and**
   `[control_plane]`: either pairing enabled is a config error.
4. Recording — `[mapping] recording = false` default; **per-grant** `policy.recording`
   (not global); mapped sessions are never recorded unless opted in, even when
   `[recording]` is configured. Documented.
5. Port default 22 and `user` default = username — **accepted**, with documented
   safety (Principal grammar) and optional explicit `user`.

## 11. Summary of semantics (what a deployer gets)

```
[mapping]
enabled = true
mapping_file = "/etc/ssh-gw/mappings.toml"
allow_any_authenticated_key = true
# recording = false        # optional; default false

# mappings.toml
[[entries]]
username = "alex"
host = "10.0.0.7"
port = 22
user = "alex"
```

`ssh alex@gateway` → front-leg key verified → router → mapping → dial
`10.0.0.7:22` as user `alex`, authenticating with the forwarded agent identity.
`ssh bob@gateway` (not in file) → refused, identical envelope to any other refusal.

No `[control_plane]` and no `[openstack]` may be present while `[mapping]` is
enabled; mapping is the sole routing authority in that mode.
