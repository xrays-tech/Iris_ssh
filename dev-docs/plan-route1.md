# Route 1 — Data-Plane Pipeline Decoupling (per-packet serial await + dual crypto)

Status: planning adjudicated by @oracle; implementation in progress.
Baseline problem: end-to-end throughput ceiling ~50 MB/s across all traffic shapes
(`docs/perf-report.md:53-67`), bottleneck is the per-packet serial relay path +
dual encryption, not copies/build/crypto. Prior `0dc281b` mpsc refactor was
reverted (`d6c4eb5`) — plain queueing does not work; copies were never actually
eliminated. Controls must keep invariants I1~I4, §3.6 bounded memory, and D11.

## 0. Source of truth (verified against repo + vendored russh-0.64.1)

| Fact | Evidence |
|---|---|
| Uplink goes through the server Handler callback `data(&mut self, channel, data: &[u8], ...)`, borrow only | russh `src/server/mod.rs:463-470` |
| russh server sends Data/ExtendedData/Eof/Close/all CHANNEL_REQUEST to the channel read half **before** invoking the handler callback | russh `src/server/encrypted.rs:1282-1311,1314-1357,1435-1687` |
| `Channel<server::Msg>` can `.split()` into `ChannelReadHalf` whose `wait()` yields **owned `Bytes`** | russh `src/channels/mod.rs:154-156,503-505`; already used in jump path `src/server/mod.rs:1092` |
| `ChannelMsg::Data { data: Bytes }`, `ExtendedData { data: Bytes, ext }` | russh `src/channels/mod.rs:27-33` |
| Request `want_reply` hardcoded `true` at the read half (same as current handler hardcodes `true`) | russh `src/server/encrypted.rs:1505,1587,1615,1630,1570`; repo `src/server/mod.rs:1381,1405,1449,1477` |
| `server::Handle` has data/extended_data/channel_success/channel_failure/eof/close/exit_status_request/disconnect | russh `src/server/session.rs:118-150,161-169,46-70,88-96` |
| Channel sender is a bounded tokio mpsc (capacity = `channel_buffer_size`, repo = 100) — gives §3.6 boundedness | russh `src/server/mod.rs:362-369`; repo `src/server/mod.rs:515` |
| Current uplink per packet: `relay.backend.data_bytes(owned).await`, owned via `to_vec()` | `src/server/mod.rs:1279,1300-1301`; `src/relay/mod.rs:706-712` |
| Downlink: russh already hands owned `Bytes`, code did `&data -> to_vec()` then `Bytes::from` (fixed in route 2) | `src/relay/mod.rs:459-472` |
| Invariant red lines I1~I4 / §3.6 | `dev-docs/propose.md:118-129,188-210` |

## 1. Design choice

**Selected: consume the server-side `ChannelReadHalf` with a new
`pump_client_to_backend`, mirroring the existing `pump_backend_to_client`.**
This is the *only* option that simultaneously (a) yields owned `Bytes` -> uplink
copy eliminated, (b) moves the data plane off the serial handler callback so the
read loop can run ahead, and (c) keeps I1 constructively (a single pump
consumes one ordered stream — requests + data + eof + close all share one
cursor). Boundedness comes from russh's bounded channel sender
(`channel_buffer_size`); the pump adds no unbounded buffer.

Rejected alternatives: read-ahead inside the serial handler (cannot own several
packets from a `&[u8]` borrow; memory bound not provable); single-writer
pipeline via handler enqueue + dedicated writer (empirically ~0 gain in
`0dc281b`; still copies and still couples the read loop); knob tuning
(max_packet/window/nodelay/ciphers/build — all measured <1%).

Symmetric shape:

```
client [russh server leg] <-> ChannelReadHalf --pump_client_to_backend--> BackendWriter [russh client leg]
                            server::Handle  <--pump_backend_to_client--- BackendReader
```

- Both pumps each own one leg's read half: crypto/en/dec overlaps with forwarding.
- I1: single pump consuming one ordered stream -> strict FIFO, no race.
- I2: read-half request `want_reply=true` matches current behavior; replies
  still flow `ReplyRouter` -> down-pump `settle` -> up-pump
  `Handle::channel_success/failure`.
- I3: pump only passes through; tap `inject` is client-bound data, never a new request.
- I4: denials use native primitives (channel_failure / open failure); never fabricate.
- §3.6: bounded by russh's channel sender; no unbounded buffering in the pump.

### GO/NO-GO measurement gate (mandatory, prevents repeating `0dc281b`)
Baseline first: pure-uplink, pure-downlink, scp (perf-report A/B/C forms).
After implementation both pure legs must gain >=15% (relative) vs baseline with
RSS not growing and latency not regressing; otherwise revert commit C3.

## 2. Change list (layered commits; C1/C2 internal, C3 the revert unit)

### C1 — Downlink zero-copy — ALREADY DONE in route 2 (commit db05543)
`apply_tap_down(tap, data: Bytes, id) -> (Bytes, Bytes)`; no-tap/`Pass` returns
the same owned Bytes (no copy); only `Rewrite` allocates. Keep as-is.

### C2 — Auditor internal mutability (internal refactor, behavior-preserving)
- `src/audit/mod.rs` `Auditor.command` -> `Mutex<Option<CommandInfo>>`;
  `set_command(&mut self)` -> `set_command(&self)` (first-command-wins);
  `finalize()` -> `&self` (lock to read command, other fields clone unchanged).
- `src/server/mod.rs`: `auditor: Option<Auditor>` -> `Option<Arc<Auditor>>`;
  `record_channel_command` uses `&self`; Drop's `finalize` adapts.

### C3 — New client->backend pump + wiring (scheduling-shape change; THE revert unit)
New `src/relay/uplink.rs`:
- `struct RelayUpstream` (per-channel state captured by the pump, replacing the
  per-packet `self.relays` lookups): client_id, backend writer, `up:
  russh::server::Handle`, router, window Arc, bytes Arc, metrics, tap Option,
  config Arc (env allowlist), interceptor (subsystem deny), entry,
  auditor Option<Arc>.
- `async fn pump_client_to_backend(mut client: ChannelReadHalf<server::Msg>, st)`
  `while let Some(msg) = client.wait().await { match msg { … } }` strictly ordered:
  - `Data { data }` -> `window.acquire(n)` (when `outbound_guard`) -> `apply_tap_up`
    -> `backend.data_bytes(bytes).await`; `bytes.add_up`.
  - `ExtendedData` -> `extended_data_bytes`.
  - `RequestPty/RequestShell/Exec/RequestSubsystem/SetEnv/WindowChange/Signal`
    -> `router.push(true)` -> `backend.xxx(true,..).await` -> await oneshot ->
    `up.channel_success/failure`.
  - `RequestSubsystem`: interceptor on_subsystem_request; `Deny` -> channel_failure;
    `Pass` -> forward; set command class + auditor command.
  - `Exec`: CommandInfo::Exec(String::from_utf8_lossy) -> channel class + auditor;
    then forward.
  - `Env`: `crate::policy::env_allowed` filtering (migrate logic).
  - `Eof` -> `backend.eof()`; `Close` -> `backend.close()` + break.
  - `AgentForward/RequestX11`: NOT handled in pump (stay on handler).
  - Exit: after `None`/`Close`, forward `backend.close()`; do NOT `window.close()`
    (down-pump owns that, preserves P0-2 liveness).
- `src/server/mod.rs` wiring:
  - `channel_open_session` (~:1130-1234): `channel.split()` after getting id; get
    `(backend_read, backend_write)`; build tap (already there) -> clone for both
    pumps; down-pump spawn unchanged; NEW up-pump spawn with `RelayUpstream`;
    `reply.accept().await` stays last.
  - `channel_open_direct_tcpip` (~:1020-1128): `_channel.split()` and spawn the
    same up-pump (jump has no requests, just data/eof/close).
  - Neutralize handler data/request callbacks (trait defaults, dead old
    forwarding; keep only local denial/cleanup): stop `data`, `extended_data`,
    `pty_request`, `shell_request`, `exec_request`, `subsystem_request`,
    `env_request`, `window_change_request`, `signal`, `channel_eof`.
    KEEP `auth_*`; keep `agent_request` (false) and `x11_request`
    (channel_failure).
  - `channel_close`: remove `relay.backend.close()` (pump forwards it); keep
    `relays.remove`, taps bookkeeping, `entry.forget_channel`.
  - tap `flush()` only in the down-pump; remove any tap flush in `channel_close`
    (no double flush).
- Per-packet cleanup inside the pump (holding state directly): zero HashMap
  lookups on the hot path; uplink zero-copy via owned Bytes (kills the upstream
  `to_vec()`); `note_would_exhaust` moved to the actual-blocking path;
  `OutboundWindow` gains a `try_acquire_many` fast path (async state machine only
  on miss).

## 3. New tests
- Unit: `apply_tap_up`/`apply_tap_down` `Pass` returns the same allocation
  (Bytes pointer equality / slice address); Auditor concurrent `set_command`
  first-wins no panic; `OutboundWindow` try_acquire fast/slow equivalence.
- Integration (extend only if harness simple; existing 18+ cases must stay
  green unchanged): `case_uplink_readahead.sh` (slow consumer + large write ->
  ordering preserved + bounded RSS), `case_request_data_order.sh`
  (pty->shell->data / exec->data ordering).

## 4. DoD (C3 delivery)
- [ ] pump_client_to_backend lands; channel_open_session and direct_tcpip both spawn; old handler data/request callbacks neutralized; no double forwarding.
- [ ] Uplink zero-copy (owned Bytes to backend.data_bytes); downlink owned pass-through.
- [ ] Full unit + full integration suite green, unchanged.
- [ ] cargo fmt --check and cargo clippy --all-targets -- -D warnings pass.
- [ ] A/B: pure-uplink and pure-downlink >=15% relative gain vs baseline, RSS/latency not regressing; recorded in docs/perf-report.md.
- [ ] §3.6 memory bound updated (channels x (channel_buffer_size x max_packet + up_window + down_window)); backpressure case RSS bounded.

Red lines (do not touch): I3 (no injected gateway requests; tap inject only
client-bound data); I4 (native denials); window semantics (`note_window` uses
backend absolute window; `close()` liveness coupling); auth/authorization/audit
format/control-plane/resolve/CA/jump policy logic; tap chain semantics
(inspector-first, recorder-second); no unbounded buffers; no await while holding
a lock (D11); no spawned async request forwarding.

Out of scope this round: cross-session connection pool / actor-izing
`client::Handle`; ProxyJump-style pass-through / raw TCP; changing
max_packet/window defaults; auth path, audit persistence, metrics semantics.

## 5. Full test command list
```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
make bench                                   # BENCH_FILE_MB/BENCH_ITERS tunable
scripts/run_integration.sh                   # full black-box suite
```
