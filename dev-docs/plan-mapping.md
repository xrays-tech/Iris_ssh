# Development Plan: Simple Mapping Mode (username → target)

Status: IMPLEMENTED (gates G1/G2/G3 passed; Phases 1-3 landed; Phase 4 verified)
Design basis: dev-docs/design-mapping.md (G1 PASS, all 6 changes incorporated + post-review room wording fix)
Repo conventions: doc plan names `plan-*.md`; commits merge as independent valid delivery boundaries.

## 0. Scope reminder (from approved design)

- New `[mapping]` config section (switch `enabled`, `mapping_file`, `allow_any_authenticated_key`,
  `recording`).
- New TOML mapping file (`[[entries]]` username/host/port/user) loaded once at build, fail-closed.
- New routing source `ResolveSource::Mapping` / `ResolveRoute::Mapping`.
- Mutually exclusive with `[openstack]` and `[control_plane]` while enabled.
- Auth: front-leg verification + `allow_any_authenticated_key` (lab mode, same as openstack).
- Feature-off = byte-inert. No hot reload v1.

## 1. Delivery phases and gates

Phases are dependency-ordered delivery boundaries; each is an independently valid,
commitable slice. Oracle gates: G2 here (plan), then an Oracle review after Phase 2
(the integration-bearing phase), and final G3 after Phase 3 (full verification).

| Phase | Deliverables | Oracle gate |
|---|---|---|
| 0 | This plan + test plan review | **G2 (now)** |
| 1 | Types (`ResolveSource::Mapping`) + pure `src/mapping` module (table/client) | — |
| 2 | Config schema + validation + router + server-build wiring + metrics; unit tests | **Oracle review (routing/build)** |
| 3 | Docs (config.example/README/runbook/known-limitations) + integration case | — |
| 4 | Final verification: lint/clippy/`make test`/integration | **G3** |

## 2. Phase 1 — Types + mapping module (pure, no config)

Owner: @fixer. Root scope: `src/types.rs`, `src/mapping/mod.rs` (new), `src/lib.rs`
(module declaration), module unit tests.

### 2.1 Types (src/types.rs)

- `ResolveSource::Mapping` variant (~types.rs:143) + `as_str() -> "mapping"`
  (~types.rs:153). Update `#[cfg(test)]` asserts that enumerate sources (~types.rs:491).
- Fact-checked ripple: `ResolveSource` is matched exhaustively ONLY in
  `types.rs::as_str`; everywhere else uses `ResolveSource::default()` (audit/policy/relay/
  backend/resolve) or assignment (audit:473) — no other match breaks compilation.

### 2.2 Mapping module (src/mapping/mod.rs, new)

- `MappingEntry { host: String, port: u16, user: String }` and conversion to
  `crate::types::Target`.
- `MappingTable::load(path) -> Result<MappingTable, ConfigError>`:
  - read file (missing/io → error); `metadata` size cap 4 MiB (error); reject symlink
    (`fs::symlink_metadata`) ; permission check `mode & 0o022 != 0` → error (threat model =
    file integrity: refuse group/other WRITE; do NOT mirror key files' `0o077` secret mask
    which would wrongly reject world-readable tables — backend/mod.rs:88 precedent);
  - deserialize Toml `{ entries: Vec<RawEntry> }` with `deny_unknown_fields` +
    `#[serde(deny_unknown_fields)]` on `RawEntry`; defaults port=22 user=username;
  - validate each: username via `parse_principal`, host non-empty & no control/whitespace/NUL,
    port 1..=65535, user non-empty; duplicate usernames → error;
  - build `HashMap<Principal, MappingEntry>`.
- `MappingClient` implementing `crate::resolve::ControlPlaneClient` (resolve/mod.rs:174):
  `resolve(req)` → hit: `ResolveResponse { target, policy { agent_forwarding: true,
  recording: <client field>, ttl: 0 } }`; miss: `Err(ControlError::NotFound)`. The client
  carries a `recording: bool` set by its constructor (wired from `[mapping] recording` in
  Phase 2).
- Module unit tests: happy path, defaults, duplicate, bad host/port/user/principal, unknown
  field, empty table (valid + warn-ready), permission/symlink/size errors, resolve hit/miss.

### 2.3 lib.rs

- `pub mod mapping;` (~lib.rs:14-28 module declarations).

Phase 1 is a **non-releasable intermediate**: it adds `ResolveSource::Mapping` and the
mapping module with no config knob exposed and no routing impact (feature-off stays
byte-inert; no `[mapping]` config exists yet). Its commit is structural groundwork, not a
half-live feature.

**Phase 1 exit:** `cargo test` green on touched modules, `cargo clippy` clean; commit
`feat(mapping): mapping table + client groundwork (plan-mapping P1)`.

## 3. Phase 2 — Config, router, server build wiring, metrics

Owner: @fixer. Root scope: `src/config.rs`, `src/resolve/router.rs`, `src/server/mod.rs`,
`src/metrics.rs`. Dependency: Phase 1 (`MappingClient`, `MappingConfig`-adjacent types).

### 3.1 Config (src/config.rs)

- `RawConfig.mapping: Option<RawMapping>` (~config.rs:565) — new `#[derive(Deserialize, Default)]`
  `RawMapping { enabled: bool, mapping_file: Option<String>, allow_any_authenticated_key: bool,
  recording: bool }`. Config section stays permissive (no `deny_unknown_fields`), matching
  `RawOpenStack`.
- `MappingConfig { enabled, mapping_file: PathBuf, allow_any_authenticated_key, recording }`
  + `GatewayConfig.mapping: Option<MappingConfig>` (~config.rs:35).
- `validate_mapping` helper with signature `validate_mapping(
    raw: Option<RawMapping>, openstack: &Option<OpenStackConfig>, raw_cp: &Option<RawControlPlane>,
  ) -> Result<Option<MappingConfig>, ConfigError>` — needs the validated `openstack` result and
  `raw.control_plane` to implement the exclusion rules, so it is called AFTER `validate_openstack`
  (config.rs:1224) and receives both. Rules:
  - absent/disabled → `None` (byte-inert);
  - enabled ⇒ `mapping_file` non-empty (else error);
  - enabled ⇒ `allow_any_authenticated_key == true` (else error; field+reason mirror
    config.rs:1436 style);
  - enabled ⇒ error if `openstack` is enabled (two authorities);
  - enabled ⇒ error if `raw_cp` present (two authorities);
  - `control_plane_required` (config.rs:1229) becomes
    `!mapping_enabled && !(openstack pure mode)` — i.e. false when mapping is enabled, so a
    mapping config without `[control_plane]` parses.
- Config unit tests (config.rs `#[cfg(test)]`): absent/disabled inert; enabled-no-file;
  enabled-without-flag; mapping+openstack; mapping+control_plane; parse happy path;
  `control_plane_required` false when mapping enabled and no CP section → valid.

### 3.2 Router (src/resolve/router.rs)

- `ResolveRoute::Mapping` (~router.rs:24).
- `ResolveRouter` fields: `mapping_enabled: bool`, `mapping: Option<Arc<Resolver>>`
  (~router.rs:230); `new(...)` gains the two params — update ALL call sites: server/mod.rs:561
  and the router unit tests (router.rs:490, 553-558, 589-596).
- `route()` (~router.rs:269): `if self.mapping_enabled { return Mapping }` then `route_for(...)`.
- `can_serve()` (~router.rs:283): `Mapping => mapping.is_some()` (ResolveRoute is matched
  exhaustively here — add the arm).
- `authorize()` (~router.rs:299-311): arm `Mapping` → mapping resolver's `authorize(...)`;
  source = `ResolveSource::Mapping`; miss → `ResolveError::NotFound`; metrics
  `mapping_resolve_latency` + ok/miss counters; stamp `grant.resolve_source`.
- Router unit tests: enabled ⇒ every principal → Mapping; can_serve; hit/miss; source stamp;
  metrics counters; isolation (mapping breaker independent of CP — reuse CountingClient
  pattern, ~router.rs:434).

### 3.3 Metrics (src/metrics.rs)

Mirror openstack (metrics.rs:52/56/107/275/291/306/514/524/631):
- `mapping_resolve_ok_total: AtomicU64`, `mapping_resolve_miss_total: AtomicU64` (miss is the
  only error outcome for an immutable table — a refused login, worth its own counter),
  `mapping_resolve_latency_us: Histogram`.
- Accessors `mapping_resolve_ok()` / `mapping_resolve_miss()` / `mapping_resolve_latency(..)`.
- Render lines `sshgw_mapping_resolve_ok_total`, `sshgw_mapping_resolve_miss_total`,
  `sshgw_mapping_resolve_latency_seconds`.
- Keep the §3.2 router-metrics wording consistent: router calls `mapping_resolve_ok()`,
  `mapping_resolve_miss()`, `mapping_resolve_latency(...)` (naming = ok/miss, not ok/err).

### 3.4 Server build (src/server/mod.rs)

- `build_with_clients(...)` (~461) gains a third injection parameter
  `mapping: Option<Arc<dyn ControlPlaneClient>>` (analogous to `openstack_client`), and the
  call sites update: `build` (server/mod.rs:445), `build_with_client` (455), and the existing
  `build_with_clients` test callers (server/mod.rs:3100 region + openstack pure-mode test path).
  From local config OR injected client, when `config.mapping` is `Some(enabled)`:
  - `MappingTable::load(path)` → on error propagate the `ConfigError` (do NOT stringify via
    `Error::io`; preserve the typed error, mirroring config.rs:1229) so the boot failure names
    the exact mapping-file problem;
  - build `MappingClient` (carrying `[mapping] recording`) and wrap in `Arc<Resolver>` (fixed
    tuning: fail_open=false, positive TTL 30s, standard breaker) — same shape as CP/OpenStack
    resolvers (~517-559);
  - pass to `ResolveRouter::new(...)`.
- `control_plane_needed` (~515): `!mapping_enabled && (!openstack_enabled || routing == Hybrid)`.
- Belt-and-braces (~582): `if mapping_enabled && !router.can_serve(ResolveRoute::Mapping)` →
  boot error.
- Startup warnings: `[mapping]` allow_any flag → `tracing::warn!` (mirror openstack/mod.rs:138);
  empty table → warn.
- Server build unit tests: wiring with injected fake CP/OS/mapping clients; belt-and-braces;
  pre-auth probe (`route()` = Mapping) performs no resolve (`auth_publickey_offered` warm-guard
  only fires for ControlPlane, ~1280).

**Phase 2 exit:** `cargo test` green, clippy clean; commit. → **Oracle gate** (routing/build review).

## 4. Phase 3 — Docs + integration case

Owner: @fixer (+ @designer not needed — docs only). Root scope: config.example.toml,
README.md, docs/ops-runbook.md, docs/known-limitations.md, tests/integration/, scripts/.

- config.example.toml: documented `[mapping]` section (switch, file, allow_any knob with the
  alarming wording, recording, mutual-exclusion note) — mirror the `[openstack]` comment style.
- README: feature list entry; ops-runbook §: mapping mode section (file perms 0600, lab-mode
  warning, no hot reload, never recorded unless opted-in); known-limitations: static-no-reload,
  recording-per-grant note, mapping mutual exclusion.
- Mapping fixture + integration case (tests/integration + scripts):
  - **Harness wiring is REQUIRED, not "follow existing style":** the existing `subtopo.sh`
    renders `_cp_toml` (a `[control_plane]` section) unless `SUBTOP_OPENSTACK` is set
    (subtopo.sh:201-205). A mapping case reusing subtopo naively would emit `[control_plane]`
    and hit the new mutual-exclusion config error. Therefore:
    (a) add a `SUBTOP_MAPPING` branch in subtopo.sh that suppresses `_cp_toml` and renders a
    `[mapping]` section (`enabled = true`, `mapping_file = <tmpdir>/mappings.toml`,
    `allow_any_authenticated_key = true`) and writes that temp mappings.toml from the case's
    fixture;
    (b) register `case_mapping_*` in scripts/run_integration.sh `ALL_CASES` (~line 488).
  - New `case_mapping_*`: drive the real binary with `[mapping] enabled` + temp mappings.toml
    + local sshd backend; assert dialed target = mapped host/port/user; unknown user → auth
    refused. Follow openstack-style case scaffolding otherwise.

**Phase 3 exit:** integration case passes in `make integration`; commit.

## 5. Phase 4 — Final verification (G3)

Owner: orchestrator + @oracle gate.

1. `cargo test` (unit), `cargo clippy -- -D warnings`, `make test`, `make lint`.
2. `make integration` (+ any mapping-specific case from Phase 3).
3. `cargo build --release` sanity.
4. @oracle reviews implementation diff vs approved design (G3, attempt 1/3 reserve).
5. Update dev-docs/design-mapping.md status → IMPLEMENTED; README regenerated if Makefile
   target exists (see git log "docs: regenerate README").

## 6. Risks & mitigations (from G1 review, folded in)

- CP-coherence: Phase 2 §3.3 formula short-circuits on `mapping_enabled`; parse-time exclusion
  guarantees coherence (§6.5 of design).
- Recording-per-grant: `[mapping] recording` default false; documented, not "global".
- Permissions: enforced at load (0o022 mask + symlink reject + size cap), fail-closed.
- No hot reload: documented in known-limitations.
- Double-load/TOCTOU: single load in `build_with_clients`; config validates path only.

## 7. Test plan (maps to design §9)

See design §9 items 1-7 as the authoritative acceptance list; Phases 1-3 above carry the
concrete unit/integration tests.

## 8. Acceptance criteria

1. Feature-off (no `[mapping]`) config is byte-inert: all existing tests pass unchanged.
2. `[mapping] enabled` + valid file: mapped user reaches mapped target (host/port/user);
   unknown user refused; agent-forwarding identity used.
3. Config errors (missing file/flag/exclusion/double-source) refuse boot with clear reasons.
4. Mapping file is fail-closed (perms/symlink/size/format/duplicates).
5. `resolve_source = "mapping"` in audit; mapping metrics render.
6. All lint/test/integration green; design doc + README updated.
