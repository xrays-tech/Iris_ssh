# Performance Investigation — Gateway Throughput Ceiling (~50 MB/s)

Status: **CLOSED** — engineering investigation and route adjudication, archived.
Date: 2026-10-12. Applies to relay/data-plane work on `main`.

This document is the executive record of a full performance investigation into
the SSH gateway's throughput ceiling (~50 MB/s), from initial code review
through architectural experiment and back. It consolidates the analysis, the
decisions, the executed routes, the measurement results, and the retained
outcome. Primary evidence lives in [`perf-report.md`](perf-report.md)
(benchmarks), [`plan-route1.md`](../dev-docs/plan-route1.md) (route-1 plan),
[`propose.md`](../dev-docs/propose.md) (architecture invariants), and
[`known-limitations.md`](known-limitations.md).

---

## 1. Trigger

A code-level review of the relay/server/backend/pool modules produced five
performance-bottleneck claims (P0 data-plane copies, P1 SessionRegistry lock +
O(N) scan, P3 ReplyRouter mutex, P4 OutboundWindow semaphore, P2 missing
cross-session backend pool). Each claim was to be adjudicated against the actual
source before any change; any fix was to be measured, not assumed.

## 2. Adjudication (@oracle, source + vendored russh-0.64.1 verified)

| Original claim | Verdict | Correction |
|---|---|---|
| P0 "double allocation" on data path (`to_vec()` + `Bytes::from`) | **Partly real, severity overstated** | `Bytes::from(Vec)` is a zero-copy takeover — there is **no second allocation**. Uplink `to_vec()` is **unavoidable**: russh's handler callback only lends `&[u8]` (`server/mod.rs:463-470`). The **downlink** copy (`Bytes -> &[u8] -> to_vec()`) is the only *genuinely redundant* one. Per-packet micro-bench: ~454 ns copy vs ~17 ns pass-through. |
| SessionRegistry `Mutex<HashMap>` + `count_from_ip` O(N) | Real code, **impact overestimated** | Only hit on new-connection establishment, not the data path; N bounded by `max_sessions`. Scale/governance item only. |
| ReplyRouter `std::sync::Mutex` | Real code, **non-issue** | Control-plane only (`want_reply`), no `.await` under lock, not on the packet path. |
| OutboundWindow `Semaphore acquire_many+forget` | Real, correctly rated minor | No-contention is ~1 atomic op; mandated by §3.6 as a liveness fuse. |
| Missing cross-session backend pool (russh `Handle` is Send-but-not-Sync) | **Accurate**, root cause correctly attributed | Main short-connection cost is the ~1 s auth anti-bruteforce backoff, not KEX. |

**Adjudicated real bottleneck**: per-packet serial `await` on the relay path +
the double SSH-session crypto chain (~50 MB/s across all traffic shapes), *not*
copies, builds, or tunables (all measured <1%: nodelay, ciphers, lto,
target-cpu, window, max_packet). Prior `0dc281b` "uplink sender task" refactor
was reverted (`d6c4eb5`) — it neither eliminated copies nor decoupled the read
loop.

## 3. Route 2 — executed & retained (commit `db05543`)

Low-risk, high-certainty cleanup of the one truly redundant copy:

- `apply_tap_down` now takes/returns owned `bytes::Bytes`; no-tap and `Pass`
  verdicts forward the buffer with **zero allocation**; only `Rewrite` allocates
  (tap-owned `Vec` takeover).
- `relays` map values `ChannelRelay` -> `Arc<ChannelRelay>` so
  `GatewaySession::data` does a **single lookup** and holds an owned handle
  across awaits.
- Fixed a stale comment claiming the uplink fast path is copy-free (russh lends
  `&[u8]`, one copy is API-constrained).
- Added `benches/downlink.rs` (criterion, 32 KiB): `downlink_no_tap` **~16.9 ns**
  vs `downlink_tap_rewrite` **~454 ns** vs `uplink_unavoidable_copy` **~479 ns**
  — proves the redundant downlink copy is gone.
- `scripts/bench.sh` chmod +x (`make bench` was broken without the exec bit).

End-to-end A/B (old vs new, same machine): via-gw scp 45.0 -> 44.1 MB/s —
**unchanged within noise**, as predicted: the copy was not the ceiling.

## 4. Route 1 — planned, executed one-shot, gated, reverted the no-gain part

**Plan** (`dev-docs/plan-route1.md`, @oracle adjudicated): decouple the data
plane by adding `pump_client_to_backend` consuming the server-side
`ChannelReadHalf` (owned `Bytes` + off the serial handler callback), symmetric
to the existing down-pump. I1 is kept constructively (one ordered stream, one
pump); boundedness from russh's bounded channel sender (§3.6). Mandatory
**GO/NO-GO gate**: pure-uplink and pure-downlink must gain >=15% (relative) with
no RSS/latency regression, else **revert** (C3 is the revert unit).

Executed (commits `aed6bf9` … `688e526`):

- **C2 — Auditor interior mutability** (kept): `Auditor.command` ->
  `Mutex<Option<CommandInfo>>`, `set_command`/`finalize` take `&self`,
  `Arc<Auditor>` in `GatewaySession`. Needed to share audit state into the pump.
- **C3 — uplink pump decoupling** (implemented, measured, **reverted**):
  `src/relay/uplink.rs` (`RelayUpstream` + `pump_client_to_backend`), wiring in
  both channel-open paths, 10 handler callbacks neutralized, uplink zero-copy via
  owned `Bytes`, zero HashMap lookups on the hot path, `OutboundWindow`
  `try_acquire` fast path.
- **sftp clippy fix** (kept): pre-existing `while_let_loop` at
  `src/sftp/mod.rs:401`, unblocked `-D warnings`.

Full verification during C3: `cargo test` 189 lib + 4 bin green; integration
**24 PASS / 2 SKIP / 1 FAIL**; the lone `case_stderr` FAIL was isolated via a
worktree A/B as a **pre-existing environment issue** (system locale zh_CN makes
`ls` report a Chinese error while the assertion expects English "No such file");
its forwarding semantics passed.

**Measurement (same-methodology alternating A/B, byte-verified):**

| Metric | Baseline | With C3 | Δ |
|---|---|---|---|
| make bench via-gw scp | 45.7 MB/s | 45.6 MB/s | ~0% |
| pure-uplink leg | 49.4 MB/s | 49.4 MB/s | ~0% |
| pure-downlink leg | 52.65 MB/s | 52.05 MB/s | ~−1% |
| via handshake | ~1166 ms | ~1163 ms | ~0% |

**Gate verdict: NO-GO** (>=15% gate, achieved ~0%). C3 reverted cleanly
(`git revert 8839f9f`, commit `688e526`). Conclusion recorded in
`perf-report.md` (commit `5abc982`).

## 5. Final conclusion

The gateway's ~50 MB/s ceiling is **not removable in the gateway implementation
layer**. After eliminating every redundant copy (route 2) and fully decoupling
the data plane from the serial handler while making uplink zero-copy and the hot
path lookup-free (route 1), throughput is unchanged. The ceiling is produced by
the two independent SSH sessions' per-packet serial crypto/decrypt chain and the
1 MB window / 32 KiB packet framing — the same conclusion reached by every prior
A/B in this project (`0dc281b`, nodelay/ciphers/lto/target-cpu/window/max_packet
all <1%).

Further gains would require touching russh's crypto/window internals or a
warpgate-style direct-pass architecture — **out of scope** for this project
(see `known-limitations.md`).

## 6. Retained outcome

- Gateway behavior and safety invariants I1~I4, §3.6 unchanged and green.
- Cleaner data path: downlink zero-copy, single-lookup uplink, verified by
  micro-bench and full test suite.
- Interior-mutable `Auditor` (C2) — infrastructure for future shared-state
  refactors.
- Full measurement infrastructure: `benches/downlink.rs` (criterion),
  `scripts/pure_legs.sh` methodology, perf-report A/B evidence chain.
- Definite negative result on pipeline decoupling — saves future attempts the
  same experiment.

## 7. Commit map

```
688e526 Revert "C3 — decouple uplink into pump_client_to_backend (revert unit)"
5abc982 docs: record route-1 C3 GO/NO-GO A/B — no gain, gate says revert
8839f9f perf: C3 — decouple uplink into pump_client_to_backend (reverted)
edbf6ae chore: clippy while_let_loop fix in sftp frame drain
aed6bf9 refactor: C2 — Auditor interior mutability (+ plan-route1.md)
db05543 perf: downlink zero-copy (owned-Bytes passthrough) + per-packet micro-bench
```

## 8. Full test command list (green baseline)

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                      # 181 lib + 4 bin green
cargo build --release
make bench                      # via-gw scp ~45 MB/s, loss ~86% (recorded)
scripts/run_integration.sh      # 24 PASS / 2 SKIP / 1 env-pre-existing FAIL (case_stderr, locale)
```

---

# Phase 2 — warpgate comparison, decisive measurements & closure (2026-10-12)

## 9. warpgate reference study

Research of warp-tech/warpgate (primary source @librarian, russh internals
verified) — motivation: warpgate is often described as "near-direct speed" for
the same dual-hop (client→gateway→target) shape.

**Findings** (evidence marked [X]=external primary-source, [F]=verified in repo/russh):
- warpgate uses **stock russh 0.63.3** (crates.io, not a fork; no custom
  transport). Its data plane is the same decoupled-pump shape we built and
  measured at ~0% gain in route-1 C3; its downlink even has an extra `to_vec()`
  copy [X].
- Its only real config differences vs our defaults: **`nodelay:true` on both
  legs** (we default false = Nagle-on), **2 MiB channel window** (russh default;
  we default 1 MB), `event_buffer_size=100` (russh default 10) [X].
- Its own issue history shows the same walls in the same scenarios: #2292 OOM
  (linear memory growth on large transfers), #2494 high-throughput stall, #459
  ~6-9x slower than direct on Ansible, #479 scp OOM. **No third-party quantified
  "near-direct" throughput evidence exists** [X].
- russh upstream: PR #653 (removed per-packet mlock, +47%, present since
  0.63.3); issue **#770 — client-side `adjust_window` has a code defect**: the
  client leg calls `adjust_window_size` with the constant `config.window_size`
  (`client/encrypted.rs:577`), so the handler's `adjust_window` return value is
  never applied — dynamic receive-window tuning is broken client-side [F].
  russh #770 also demonstrates receive window is the dominant throughput lever
  (2 MiB → 560 MiB/s, 4 KiB → 92, 1 KiB → 28) [X].

**Adjudication of an external "ChannelWriter" proposal** (another AI's analysis
claiming 3-10x from a dedicated writer / event-driven / per-channel tasks): its
claimed mechanism is exactly route-1 C3 (already implemented, measured ~0%,
reverted); its "warpgate zero-copy" claim is false (warpgate has a downlink
`to_vec`); its 150-500 MB/s predictions are unsourced. **Rejected.** The only
real differences are the two config flags above, which we then measured (T2).

## 10. Decisive measurements T1 & T2 (merged with oracle decision tree)

### T1 — single-leg throughput (only ONE SSH crypto pass; decisive fork)

Harness: minimal russh echo server + russh client in `/tmp/leg-single`
(independent project; no production code touched). 64 MiB, 5 runs, medians,
byte-verified, loopback; negotiated aes256-gcm (L1) / chacha20 (L2).

| Leg | up | down | round-trip |
|---|---|---|---|
| **L0** OpenSSH→OpenSSH (baseline ref) | 377.7 | 330.2 | 256.4 MB/s |
| **L1** OpenSSH→russh server | 480.8 | 322.3 | 478.7 MB/s |
| **L2** russh client→OpenSSH sshd | 301.1 | 368.4 | 218.8 MB/s |

→ **min ≈ 219 MB/s ≫ 50 MB/s: a single SSH leg saturates far above the gateway
ceiling.** Crypto is **not** the bottleneck; removing one hop's encryption
cannot produce the ~6x gap. Architecture-level de-encryption (route C) is
**negated**.

### T2 — pure-leg nodelay × window A/B (warpgate-aligned blind spot)

`scripts/pure_legs.sh` (committed), same-methodology via-gateway, 64 MB, 2×3,
byte-verified, alternating:

| config | pure-up | pure-down |
|---|---|---|
| baseline (nodelay=false, 1 MB) | 49.6 | 52.8 |
| nodelay=true, 1 MB | 53.0 | 54.6 |
| nodelay=false, 2 MB | 49.2 | 51.8 |
| nodelay=true, 2 MB (=warpgate) | 53.2 | 54.6 |
| nodelay=true, 8 MB | 46.3 | 54.6 |

→ best cell +7.3% up / +3.4% down — **no combination reaches the ≥10% gate**.
No default-config change is warranted by this axis; warpgate-aligned
`nodelay+2MiB` does not reproduce its reported performance. Blind spot closed.

## 11. Final decision-tree outcome

| Route | Verdict | Basis |
|---|---|---|
| A — config convergence (window 2 MiB / nodelay default) | **NO-GO** (gate ≥10%) | T2: window ~0%, nodelay +7~8% (below bar, no default flip) |
| B — russh upstream patch (#770 dynamic window / half-window eager top-up) | **GO-candidate — only remaining lever** | T1 ⇒ window/refill scheduling is the binding constraint; targets the effective-window ÷ refill-RTT model; conservative +15~30% [S] |
| C — architecture de-encryption (bare TCP / local channel / ProxyJump) | **NO-GO** | T1 single-leg ≫50 ⇒ crypto not the limit; ProxyJump also violates gateway auth/audit requirement |
| T3 — window-refill RTT / binding-window diagnostic | next measurement | corroborates B before any fork |
| T10 — record ceiling, pivot KPI to connection-level | fallback | if B declined / fails |

**Conclusion**: the ~50 MB/s ceiling is a dual-SSH-chain **window/refill
scheduling** limit (effective receive window of the opponent leg ÷ refill
round-trip across both legs and per-chunk mpsc hops), not implementation copies,
scheduling shape, or crypto. Single-leg plumbing does ~220-480 MB/s on this
host; the gateway spends the rest on window-refill round-trips. The single
promising lever left is a russh upstream patch (B), which requires forking /
vendoring russh — a maintenance commitment to approve explicitly.
